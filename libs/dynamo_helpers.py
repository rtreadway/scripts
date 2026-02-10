''''''

from decimal import Decimal
import math
from collections import defaultdict
import os
from functools import lru_cache
from itertools import zip_longest

import jsonpointer
import botocore
import boto3
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

from .helpers import NMPrintableError, try_convert_to_int

class TransactionConflict(Exception):
    """Issue with a DyanmoDB Transaction."""
    pass

class DynamoStoreFailed(NMPrintableError):
    """Storing to DynamoDB failed."""
    pass

@lru_cache
def get_dynamo_resource(): # pragma: no cover
    return boto3.resource('dynamodb') # pylint: disable=no-member

@lru_cache
def get_dynamo_table(dynamo_table_name): # pragma: no cover
    """Get a DynamoDB Table object from a boto3 DynamoDB Resource."""
    return get_dynamo_resource().Table(dynamo_table_name) # pylint: disable=no-member

@lru_cache
def get_dynamo_key_schema(table_name):
    """Get the key schema for a DynamoDB table."""
    return get_dynamo_table(table_name).key_schema

@lru_cache
def get_dynamo_primary_key_name(table_name): # pragma: no cover
    """Get the Primary Key's name from a DynamoDB table schema."""
    key_schema = get_dynamo_key_schema(table_name)
    if len(key_schema) == 1:
        return key_schema[0]["AttributeName"] # NOTE: we don't support composite pks at this point...
    else: # Note: order matters in key_schema
        return tuple(schema_itemD["AttributeName"] for schema_itemD in sorted(key_schema, key=lambda sD: sD["KeyType"] != "HASH"))

@lru_cache
def get_table_info(table_name):
    """Get table attributes.

    Args:
        table_name (str): DynamoDB table name.

    Returns:
        dict[tuple]: {attribute_name: (attribute_definition, key_type)}.
    """
    attribute_definitions = get_dynamo_table(table_name).attribute_definitions
    attribute_definitionsD = {attrD["AttributeName"]: attrD["AttributeType"] for attrD in attribute_definitions}
    
    attrs = [ (schema_itemD["AttributeName"], (attribute_definitionsD[schema_itemD["AttributeName"]], schema_itemD["KeyType"])) for schema_itemD in get_dynamo_key_schema(table_name) ]
    attrs.sort(key=lambda schema_itemD: schema_itemD[1][1] != "HASH") # This won't work if a third keytype is added to dynamo.  
    
    return dict(attrs)

# This doesn't help because we would need to reverse coerce after the records have been received
def coerce_key(primary_key, attr_def):  # pragma: no cover
    """Coerce a primary key from DynamoDB type S or N to a respective 
    Python type. Otherwise return the key.
    
    "S" -> str.\n
    "N" -> Decimal.

    Args:
        primary_key (any): primary key.
        attr_def (list): Dynamo attribute types.

    Returns:
        The coerced key if Dynamo type S or N, else the key as-is.
    """    
    if attr_def[0] == "S" and not isinstance(primary_key, str):
        return str(primary_key)
    elif attr_def[0] == "N" and not isinstance(primary_key, (int, float, Decimal)):
        return Decimal(primary_key)
    else:
        return primary_key

def get_dynamo_primary_keys(table_name, primary_keys): # pragma: no cover
    """Get the primary key(s) values from a DynamoDB table.

    Args:
        table_name (str): DynamoDB table name.
        primary_keys (list | tuple): collection of primary key names.

    Returns:
        dict: {attribute_name : pk}.
    """    
    table_infoD = get_table_info(table_name)
    
    if not isinstance(primary_keys, (list, tuple)):
        return {get_dynamo_primary_key_name(table_name): coerce_key(primary_keys, list(table_infoD)[0][1])}
    
    ret_val = {}
    for i, attr_name in enumerate(table_infoD.keys()):
        ret_val[attr_name] = primary_keys[i]
    return ret_val

def get_dynamo_record(table_name, primary_key, consistent_read=False): # pragma: no cover
    """Get a DynamoDB record for the given primary key.

    Args:
        table_name (str): DynamoDB table name.
        primary_key (str): primary key.
        consistent_read (bool, optional): If True, Dynamo uses strongly consistent reads, ensuring the latest data, but uses more resources. Otherwise uses 'eventually consistent' reads, which may return and older version of the data. Defaults to False.

    Returns:
        dict | None: "Item" from the DynamoDB response containing the 
            record, or None if no item found for the key.
    """
    dynamo_response = get_dynamo_table(table_name).get_item(Key=get_dynamo_primary_keys(table_name, primary_key), ConsistentRead=consistent_read)
    if "Item" in dynamo_response:
        return dynamo_response["Item"]
    else:
        return None

def get_dynamo_records(recordL, fieldL=None): # pragma: no cover
    """ Retrieves records from DynamoDB based on specified table names and  
    primary keys. Optionally filters fields in the records.

    Fetches records from DynamoDB for each table name & primary key 
    combination in 'recordL'.
    Optionally filters returned fields based on 'fieldL'. Utilizes batch get requests and processes unprocessed keys in subsequent requests. 
    Supports field projection in DynamoDB and can consistently read 
    records in a testing environment.

    Args:
        recordL (list[tuple]):  each tuple contains a table name & primary key 
        fieldL (list[str], optional): list of field names to return in JSONPointer notation. Defaults to None.

    Returns:
        dict[tuple:dict]: entries are in the form 
            {(table_name, primary_key): dynamo_record}
            If record isn't found for a tuple combo, the record is set
            to None
            
    Note:
        - This function uses batch get item requests to DynamoDB.
        - The 'fieldL' argument supports JSON Pointer notation for nested 
        fields.
        - In a testing environment (determined by 'ENV_NAME' environment 
        variable), the function performs consistent reads from DynamoDB.
    """
    # Format records for request to DynamoDB
    requested_itemD = defaultdict(lambda: defaultdict(list))
    for (table_name, primary_key) in recordL:
        requested_itemD[table_name]["Keys"].append(get_dynamo_primary_keys(table_name, primary_key))
    
    # Set projection
    if fieldL:
        expression_attribute_names = {}
        field_stringL = []
        for i, projection_name in enumerate(fieldL):
            projection_name = "/" + projection_name
            field_aliasL = []
            for j, field_part_name in enumerate(jsonpointer.JsonPointer(projection_name).get_parts()):
                field_alias = "#" + chr(ord("A") + (i // 26)) + chr(ord("A") + (i % 26)) + chr(ord("A") + j)
                field_aliasL.append(field_alias)
                expression_attribute_names[field_alias] = field_part_name # Translate field_names to a 3 letter code
            field_stringL.append(".".join(field_aliasL))
        
        field_string = ",".join(field_stringL)
        for tableD in requested_itemD.values():
            tableD["ExpressionAttributeNames"] = expression_attribute_names
            tableD["ProjectionExpression"] = field_string
            tableD["ConsistentRead"] = True if os.environ.get("ENV_NAME", "") == "test" else False
    
    # Call Dynamo
    ret_val = {}
    while requested_itemD:
        dynamo_response = get_dynamo_resource().batch_get_item(RequestItems=requested_itemD, ReturnConsumedCapacity='NONE') # pylint: disable=no-member
        
        # Format records to return
        ret_val.update({ (table_name, dynamo_item[get_dynamo_primary_key_name(table_name)]): dynamo_item for table_name, itemL in dynamo_response['Responses'].items() for dynamo_item in itemL })
        
        requested_itemD = dynamo_response.get("UnprocessedKeys")
    
    # Populate non-existing items
    for (table_name, primary_key) in recordL:
        if (table_name, primary_key) not in ret_val:
            ret_val[(table_name, primary_key)] = None
    
    return ret_val

class MyTypeSerializer(TypeSerializer): # pragma: no cover
    def _is_number(self, value):
        if isinstance(value, (int, float, Decimal)):
            return True
        else:
            return False
    
    def _serialize_n(self, value):
        return str(value) # Floats don't happen very often in our code and we don't need to maximize space, so this will work.  

DYNAMO_SERIALIZER = MyTypeSerializer()
def convert_dict_to_dynamo_client_format(item, top_level=True): # pragma: no cover
    """Convert a Python value or collection to a DynamoDB client compatable
    format. Handles None, bool, str, int, float, Decimal, list and dict.
    
    NOTE: this was done before I knew there was build-in functionailty to do this.  Use DYNAMO_DESERIALIZER directly from now on.      """
    return DYNAMO_SERIALIZER.serialize(item)["M"]

class MyTypeDeserializer(TypeDeserializer): # pragma: no cover
    def _deserialize_n(self, value):
        float_value = float(value)
        int_value = int(float_value)
        return int_value if int_value == float_value else float_value

DYNAMO_DESERIALIZER = MyTypeDeserializer()
def convert_dynamo_client_format_to_dict(item): # pragma: no cover
    """
    Convert a dict in DynamoDB Client format to a Pythonic dict.  NOTE: this was done before I knew there was build-in functionailty to do this.  Use DYNAMO_DESERIALIZER directly from now on.  
    """
    return DYNAMO_DESERIALIZER.deserialize({"M": item})

def store_dynamo_record(dynamo_table_name, dynamo_record, force_version=False): # pragma: no cover
    """Stores a DynamoDB record with optional version control.

    If 'force_version' is not set, the function performs a conditional put 
    operation to ensure version control. It checks if the 'version' attribute of
    the record either does not exist (for new records) or matches the 
    previous version (for updates).

    Args:
        dynamo_table_name (str): DynamoDB table where the record is to be stored.
        dynamo_record (dict): The record to be stored. It must contain a 'version' key if 'force_version' is False.
        force_version (bool, optional): If True, the record is stored without version   checking. If False, the function performs version control based on the 'version' attribute in 'dynamo_record'. Defaults to False.

    Raises:
        boto3.dynamodb.exceptions.ConditionalCheckFailedException: If the version control check fails.

    Note:
        - function assumes that the 'version' attribute in 'dynamo_record' is an integer that increments with each update.
        - The 'version' attribute is used for concurrency control to prevent overwriting changes made by concurrent operations.
    """
    if force_version:
        get_dynamo_table(dynamo_table_name).put_item(Item=dynamo_record)
        return
    
    old_version = dynamo_record["version"] - 1
    if old_version:
        get_dynamo_table(dynamo_table_name).put_item(Item=dynamo_record, ConditionExpression=boto3.dynamodb.conditions.Attr("version").eq(old_version))
    else:
        get_dynamo_table(dynamo_table_name).put_item(Item=dynamo_record, ConditionExpression=boto3.dynamodb.conditions.Attr("version").not_exists())

def store_dynamo_records(recordL, force_version=False, transactional=True): # pragma: no cover
    """Handles storing a list of DynamoDB records in a transactional or 
    non-transactional fashion, selected by the 'transactional' flag.

    Args:
        recordL (list[tuple]): each element is a tuple containing the table name, primary key, and the item to be stored. The structure is ((table_name, primary_key), item).
        force_version (bool, optional): If True, each record is stored without version checking.. Defaults to False.
        transactional (bool, optional): If True, the records are stored using transactional logic. Defaults to True.

    Returns:
        function: call to the transactional or non-transactional method of DynamoDB record storage, depending on the 'transactional' flag.
    """
    if transactional and len(recordL) > 1:
        return store_dynamo_records_transactional(recordL, force_version)
    else:
        return store_dynamo_records_non_transactional(recordL, force_version)

def store_dynamo_records_non_transactional(recordL, force_version=False): # pragma: no cover
    """Stores a list of records in a non-transactional fashion.

    Iterates over a list of records and stores each in the specified DynamoDB table. 
    Uses `store_dynamo_record` for storing individual records. If 'force_version' is  
    False, version control checks are performed for each record. In case of a version 
    control conflict, and if there's only one record, it raises a TransactionConflict exception.

    Args:
        recordL (list[tuple]): each element is a tuple containing the table name, primary key, and the item to be stored. The structure is ((table_name, primary_key), item).
        force_version (bool, optional): If True, each record is stored without version checking. Defaults to False.

    Raises:
        TransactionConflict: When there's a version control conflict during the storage of a single record (ConditionalCheckFailedException).
        botocore.exceptions.ClientError: Other DynamoDB client errors.

    Note:
        - The function is non-transactional, meaning each record is stored independently. Failure to store one record 
          does not affect others.
        - This function is particularly useful when dealing with multiple records that need to be stored separately
          and where transactional consistency is not required.
    """
    for (table_name, _primary_key), item in recordL:
        try:
            store_dynamo_record(table_name, item, force_version)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "ConditionalCheckFailedException" and len(recordL) == 1: # We can only recover from this if there is only 1 record that failed.  
                raise TransactionConflict() from e # The record has been updated in the database.  We'll need to re-calculate everything...
            else:
                raise

def store_dynamo_records_transactional(recordL, force_version=False): # pragma: no cover
    """Transactional handling of multiple records in select DynamoDB tables.

    Performs transactional write operations (put, update, delete) in DynamoDB for a 
    list of records. Each record operation is atomic and all operations either succeed 
    or fail together. It handles conditional checks for version control unles 
    'force_version' is set to True. The function retries the transaction up to
    five times in case of 'TransactionCanceledException'.

    Args:
        recordL (list[tuple]): each element is a tuple containing the table name, primary key, and the item to be stored. The structure is ((table_name, primary_key), item). NOTE: The item data should include a 'version' key.
        force_version (bool, optional): If True, each record is stored without version checking. Defaults to False.

    Raises:
        TransactionConflict: Raised if a conditional check fails due to a version mismatch.
        DynamoStoreFailed: Raised if the transaction fails after the max number of retries.

    Returns:
        dict: The response from the DynamoDB 'transact_write_items' operation.

    Note:
        - The function supports 'Put', 'Delete', and 'ConditionCheck' operations based on the provided item data.
        - The 'version' attribute in the item data is used for optimistic concurrency control.
        - The function retries the transaction up to five times in case of 'TransactionCanceledException'.
    """
    client = boto3.client("dynamodb")
    
    new_itemL = []
    for (table_name, _primary_key), item in recordL:
        primary_key_name = get_dynamo_primary_key_name(table_name)
        
        if item["version"] < 0:
            verb = 'Delete'
            new_itemL.append({verb: {'Key': convert_dict_to_dynamo_client_format({primary_key_name: item[primary_key_name]}), 'TableName': table_name}})
        elif len(item) == 2 and "Key" in item and "version" in item:
            verb = 'ConditionCheck'
            new_itemL.append({verb: {'Key': convert_dict_to_dynamo_client_format({primary_key_name: item["Key"]}), 'TableName': table_name, 
                                            'ReturnValuesOnConditionCheckFailure': 'NONE'}})
        else:
            verb = 'Put'
            new_itemL.append({verb: {'Item': convert_dict_to_dynamo_client_format(item), 'TableName': table_name}})
        
        if not force_version:
            if verb == 'ConditionCheck':
                if item["version"] == 0:
                    new_itemL[-1][verb]['ConditionExpression'] = "attribute_not_exists(%s)" % primary_key_name
                else:
                    new_itemL[-1][verb]['ConditionExpression'] = "version = :version"
                    new_itemL[-1][verb]["ExpressionAttributeValues"] = {":version": {"N": str(item["version"])}}
            elif item["version"] > 1:
                new_itemL[-1][verb]['ConditionExpression'] = "version = :version"
                new_itemL[-1][verb]["ExpressionAttributeValues"] = {":version": {"N": str(item["version"] - 1)}}
            elif item["version"] == 1:
                new_itemL[-1][verb]['ConditionExpression'] = "attribute_not_exists(%s)" % primary_key_name
            else: # Version <= 0
                new_itemL[-1][verb]['ConditionExpression'] = "version = :version"
                new_itemL[-1][verb]["ExpressionAttributeValues"] = {":version": {"N": str(1)}}
    
    for i in range(5):
        try:
            # It turned out this guy (ie transact_write_items) isn't any faster than 10 put_item calls.  (But it's still atomic so it has it's use).
            return client.transact_write_items(TransactItems=new_itemL)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "ConditionalCheckFailedException":
                raise TransactionConflict() from e # The record has been updated in the database.  We'll need to re-calculate everything...
            elif e.response['Error']['Code'] == "TransactionCanceledException":
                if i == 4:
                    raise DynamoStoreFailed(e.response['Error']['Code'] + ": " + e.response['Error'].get('Message', "Error Message Missing"))
                else:
                    continue
            else:
                raise

def delete_dynamo_records(recordL): # pragma: no cover
    """ Deletes multiple records from DynamoDB tables in batches.

    This function performs batch deletion operations in DynamoDB. It processes 
    the list of records ('recordL'), where each record is a tuple containing 
    the table name and primary key. The function handles the batch deletion 
    in chunks of 25 records, as this is the maximum batch size for DynamoDB 
    batch write operations.

    Args:
        recordL (list of tuple): A list where each element is a tuple containing the DynamoDB table name and the primary key of the record to be deleted. The structure is (table_name, primary_key).

    Note:
        - The function divides the list of records into batches of 25 and sends batch delete requests to DynamoDB.
        - If a batch delete operation partially succeeds, the function retries deletion for the unprocessed records.
        - This function does not return a value but deletes the specified records from DynamoDB.
    """
    for batch_num in range(math.ceil(len(recordL) / 25)):
        batchL = recordL[batch_num*25:(batch_num+1)*25]
        
        table_to_recordsD = defaultdict(list)
        for (table_name, primary_key) in batchL:
            table_to_recordsD[table_name].append(primary_key)
        
        RequestItems={
            table_name: [
                {
                    'DeleteRequest': {
                        'Key': get_dynamo_primary_keys(table_name, primary_key_value)
                    }
                } for primary_key_value in table_recordL
            ] for table_name, table_recordL in table_to_recordsD.items()
        }
        
        while RequestItems:
            dynamo_response = get_dynamo_resource().batch_write_item(
                RequestItems=RequestItems,
                ReturnConsumedCapacity='NONE', ReturnItemCollectionMetrics='NONE'
            )
            RequestItems = dynamo_response.get("UnprocessedKeys")
