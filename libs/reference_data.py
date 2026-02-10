'''Related to the initialization of Reference Cache data and access of said data.
Used in Business Rule logic, the API and in some utilities'''

import os
import sys
import json
import logging

# sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from .helpers import convert_value, NMProgrammingError
from .dynamo_helpers import get_dynamo_table, get_dynamo_records

logger = logging.getLogger("referenceData")

__REFERENCE_DATA_INITIALIZED = False
REFERENCE_DATA = {} # will store all reference data from Dynamo + Files
REFERENCE_DATA_INDEXES = {} # will store reference data indexes

# Formatting directives for fields in reference-cache data
REFERENCE_DATA_FIELD_CONFIG = {
    "ai-domain-precedence": {},
    "education-period": {},
    "state": {},
    "event-hold-type": {},
    "pubs-country": {
        "create_dt": {"type": "string", "format": "date-time"},
        "update_dt": {"type": "string", "format": "date-time"}
    },
    "pubs-major": {
        "create_dt": {"type": "string", "format": "date-time"},
        "update_dt": {"type": "string", "format": "date-time"}
    },
    "major": {},
    "gpo-reason": {
        "create_dt": {"type": "string", "format": "date-time"},
        "update_dt": {"type": "string", "format": "date-time"}
    },
    "asmt-event": {
        "createTs": {"type": "string", "format": "date-time"},
        "updateTs": {"type": "string", "format": "date-time"}
    }, 
    "asmt-event-option-dates": {
        "eventOptionStartDt": {"type": "string", "format": "date-time"},
        "createTs": {"type": "string", "format": "date-time"},
        "updateTs": {"type": "string", "format": "date-time"}
    },
    "metrics-calculation": {},
    "country": {}
}
# Indexing definitions for DynamoDB reference-cache types
DYNAMO_INDEXES = {
    "state": {
        "default": {
            "unique": True,
            "keys": ["code"]
        }
    },
    "pubs-country": {
        "default": {
            "unique": True,
            "keys": ["code"]
        }
    },
    "pubs-major": {
        "default": {
            "unique": True,
            "keys": ["code"]
        },
        "by_sdq": {
            "unique": True,
            "keys": ["sdq_major_cd"]
        }
    },
    "major": {
        "default": {
            "unique": True,
            "keys": ["code"]
        }
    },
    "ai-domain-precedence": {
        "default": {
            "unique": True,
            "keys": ["code"]
        }
    },
    "gpo-reason": {
        "default": {
            "unique": True,
            "keys": ["code"]
        }
    },
    "education-period": {
        "default": {
            "unique": True,
            "keys": ["code"]
        }
    },
    "asmt-event": {
        "default": {
            "unique": True,
            "keys": ["asmtEventId"]
        },
        "by_year": {
            "unique": False,
            "keys": ["adminYear"]
        }
    }, 
    "asmt-event-option-dates": {
        "default": {
            "unique": True,
            "keys": ["asmtEventId", "eventOptionDateTypeCd"]
        }
    },
    "event-hold-type": {
        "default": {
            "unique": True,
            "keys": ["code"]
        }
    },
    "metrics-calculation": { # This is 2023
        "default": {
            "unique": True,
            "keys": ["scaledScore", "educationLevelCd", "educationPeriodCd"]
        }
    },
    "metrics-calculation-2024": {
        "default": {
            "unique": True,
            "keys": ["scaledScore", "educationLevelCd", "educationPeriodCd"]
        }
    },
    "country": {
        "default": {
            "unique": True,
            "keys": ["code"]
        }
    },
    "user-percentiles": { # This is 2023
        "default": {
            "unique": True,
            "keys": ["statePercentileGroup", "educationLevelCd"]
        }
    },
    "user-percentiles-2024": {
        "default": {
            "unique": True,
            "keys": ["statePercentileGroup", "educationLevelCd"]
        }
    }
}

def initialize_reference_file(reference_jsonD):
    """Initializes the data from a loaded JSON reference file"""
    table_name = reference_jsonD["table_name"]
    # Convert data types
    for row in reference_jsonD["table_data"]:
        for field_name, fieldD in reference_jsonD.get("field_config", {}).items():
            row[field_name] = convert_value(row[field_name], fieldD)
    
    REFERENCE_DATA[table_name] = reference_jsonD["table_data"]
    REFERENCE_DATA_INDEXES[table_name] = {}
    process_indexes_data(table_name, reference_jsonD["table_data"], reference_jsonD.get("indexes", {}))

def process_indexes_data(reference_data_type, data, indexes):
    """Populates the global REFERENCE_DATA_INDEXES dict with data from the DynamoDB 
    Reference-cache for the given reference data type according to the 
    definitions in DYNAMO_INDEXES

    Args:
        reference_data_type (str): the reference data type i.e. 'major'
        data (list): dynamodb data from reference-cache
        indexes (dict): index data from DYNAMO_INDEXES

    Raises:
        NMProgrammingError: when the access keys are not defined in 
            DYNAMO_INDEXES for the reference data type
    """
    for index_name, index_definitionD in indexes.items():
        assert index_name not in REFERENCE_DATA_INDEXES[reference_data_type]
        index_dataD = REFERENCE_DATA_INDEXES[reference_data_type][index_name] = {}
        if len(index_definitionD.get("keys") or []) < 1:
            raise NMProgrammingError("You must specify keys for reference data in table '%s' and index '%s'" % (reference_data_type, index_name)) # pragma: no cover
        
        for row in data:
            if len(index_definitionD["keys"]) == 1:
                key = row[index_definitionD["keys"][0]]
            else:
                key = tuple(row[field_name] for field_name in index_definitionD["keys"])
            
            if index_definitionD.get("unique"):
                assert key not in index_dataD
                index_dataD[key] = row
            else:
                index_dataD[key] = index_dataD.get(key, [])
                index_dataD[key].append(row)

def initialize_reference_data(reference_table_name=None, reload=False, dynamo_table_names=None):
    """Handles initialization of reference data sourced from DynamoDB and JSON
    reference files.
    
    The global __REFERENCE_DATA_INITIALIZED is used to avoid unnecessary reloading,
    but can be overridden by setting 'reload' to True.

    Args:
        reference_table_name (str, optional): The full DynamoDB reference-cache table name. Defaults to None.
        reload (bool, optional): Reload the reference data. Defaults to False.
    """
    global __REFERENCE_DATA_INITIALIZED
    if __REFERENCE_DATA_INITIALIZED and not reload:
        return
    
    logger.info("Initializing Reference Data")
    logger.debug("Initializing Reference Data Files")
    initialize_reference_data_from_files()
    logger.debug("Finished Initializing Reference Data Files")
    
    if not reference_table_name:
        reference_table_name = os.environ.get("DYNAMO_REFERENCE_TABLE_NAME")
    
    logger.info({"message": "Initializing Reference Data from Dynamo", "tableName": reference_table_name})
    initialize_reference_data_from_dynamo(reference_table_name, dynamo_table_names)
    logger.debug("Finished Initializing Reference Data")
    
    __REFERENCE_DATA_INITIALIZED = True

def initialize_reference_data_from_files():
    """Loads the JSON reference files as objects, then initializes the data
    for querying.

    Raises:
        NMProgrammingError: When loading a reference file produces an error
    """    
    for root, _dirs, filenames in os.walk(os.path.join(os.path.dirname(__file__), "reference")):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            # if table_names is not None and filename.split(".")[0] not in table_names:
            #     logger.info({"message": "Skipping reference file", "filename": file_path})
            #     continue
            logger.info({"message": "Loading Reference File", "filename": file_path})
            with open(file_path) as f:
                reference_jsonD = json.load(f)
            
            try:
                logger.info({"message": "Processing Reference File", "filename": file_path})
                initialize_reference_file(reference_jsonD)
            except Exception as e: # pragma: no cover
                raise NMProgrammingError("Error processing file: '%s'" % file_path) from e # May or may not be a programming error.. 
    logger.info("Finished Loading Reference Files")

def initialize_reference_data_from_dynamo(reference_table_name, dynamo_table_names=None):
    """Collects and prepares data from the specified DynamoDB reference-cache table,
    then stores it in the global REFERENCE_DATA
    
    Skips any reference data type not explicitly defined in DYNAMO_INDEXES.

    Args:
        reference_table_name (str): The full DynamoDB reference-cache table name. 

    Raises:
        NMProgrammingError: When a reference data type is unknown
    """
    if dynamo_table_names is None:
        logger.info("Loading All Reference Data from Dynamo")
        result = get_dynamo_table(reference_table_name).scan()
        dynamo_recordL = []
        dynamo_recordL.extend(result["Items"])
        while result.get("LastEvaluatedKey"):
            result = get_dynamo_table(reference_table_name).scan(ExclusiveStartKey=result["LastEvaluatedKey"])
            dynamo_recordL.extend(result["Items"])
    else:
        dynamo_recordL = get_dynamo_records([(reference_table_name, table_name) for table_name in dynamo_table_names]).values()
    
    logger.info({"message": "Loaded Records", "numReferenceRecords": len(dynamo_recordL)})
    
    for record in dynamo_recordL:
        if not record: # This would be a filename in the `table_names`
            continue
        
        reference_data_type = record['apiId'].split(':')[2]
        if reference_data_type not in DYNAMO_INDEXES:
            continue
        
        api_response = record['response']
        logger.info({"message": "Processing Reference Record", "referenceRecordType": reference_data_type})
        if reference_data_type in ("asmt-event", "asmt-event-option-dates") or \
                        reference_data_type.startswith("metrics-calculation") or reference_data_type.startswith("user-percentiles"):
            dynamo_records = api_response
            for record in dynamo_records:
                convert_reference_fields(record, reference_data_type)
        elif "cdRefList" in api_response:
            dynamo_records = transform_dynamo_response(api_response["cdRefList"], reference_data_type)
        else:
            raise NMProgrammingError(f"Unknown reference data record type for {reference_data_type}!!")
        
        REFERENCE_DATA[reference_data_type] = dynamo_records
        REFERENCE_DATA_INDEXES[reference_data_type] = {}
        
        if reference_data_type in DYNAMO_INDEXES:
            process_indexes_data(reference_data_type, dynamo_records, DYNAMO_INDEXES[reference_data_type])

def convert_reference_fields(record, reference_data_type):
    """For a given reference data type, formats select fields as specified in
    REFERENCE_DATA_FIELD_CONFIG

    Args:
        record (dict): DynamoDB record for the reference data type
        reference_data_type (str): the reference data type i.e. 'major'
    """
    # Convert data types
    field_config = REFERENCE_DATA_FIELD_CONFIG.get(reference_data_type, {})
    for field_name, fieldD in field_config.items():
        record[field_name] = convert_value(record[field_name], fieldD)

def transform_dynamo_response(api_response, reference_data_type):
    """Transforms the data returned from DynamoDB reference-cache by 
    flattening the 'attributes' section and reformatting any fields specified
    in REFERENCE_DATA_FIELD_CONFIG

    Args:
        api_response (dict): the response from DynamoDB
        reference_data_type (str): the reference data type i.e. 'major'

    Returns:
        list: The transformed response data
    """    
    transformed_response = []
    for record in api_response:
        transformed_record = {}
        
        # Copy base items over
        for item_name, item_value in record.items():
            if item_name != "attributes":
                transformed_record[item_name] = item_value
        # Copy attributes
        for attribute in record["attributes"]:
            transformed_record[attribute["name"]] = attribute["value"]
        
        convert_reference_fields(transformed_record, reference_data_type)
        transformed_response.append(transformed_record)
    return transformed_response

def get_reference_data(table_name, table_key, index_name="default", default=None):
    """Query the loaded reference data table/type by the value of it's primary key.

    Args:
        table_name (str): The DynamoDB reference data type, or the 'table_name' of the target JSON reference file
        table_key (str): primary key value to query data by. Specified in the 'keys' designation in DYNAMO_INDEXES or a JSON reference file.
        index_name (str, optional): the index which defines the primary key to query by.  Defined in DYNAMO_INDEXES or the 'indexes' section of a JSON reference file. Defaults to "default".
        default (any, optional): Default value to return if the query returns nothing. Defaults to None.

    Returns:
        str: The result of the query, or the default value
    """
    return REFERENCE_DATA_INDEXES.get(table_name, {}).get(index_name, {}).get(table_key, default)

def get_reference_table(table_name):
    """Returns the entire data structure for the given DynamoDB reference-cache type
    or JSON reference file table name.
    """
    return REFERENCE_DATA[table_name]

def clear_reference_data():
    REFERENCE_DATA.clear()
    REFERENCE_DATA_INDEXES.clear()
