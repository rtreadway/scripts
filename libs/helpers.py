from datetime import datetime

class NMPrintableError(Exception):
    """Base class for NM Errors 
    
    Don't throw this directly, use subclasses or subclass if necessary.  
    The error message from subclasses will be printed to the logs, 
    so ensure it doesn't contain sensitive information!!
    """

class NMUnknownError(NMPrintableError):
    """Something went wrong, but we're not sure why.  Possibly Recoverable"""

class UnrecoverableError(NMPrintableError):
    """Caught by the Lambda main function, which takes error actions 
    and then tells the Lambda framework that the request completed 
    (to ensure it won't re-try the operation)."""

class DatabaseRollbackFailedError(UnrecoverableError):
    """Unrecoverable failure of database rollback"""
    def __init__(self, message, body):
        self.args = (message,)
        self.body = body

class NMProgrammingError(UnrecoverableError):
    """Unrecoverable general programming error"""
    pass

class DataError(UnrecoverableError):
    """Unrecoverable data error"""
    pass

def convert_date_from_string(value):
    """ Converts a date string or a timestamp to a datetime object.
    Handles various formats of date strings and numeric timestamps.
    
    Args:
        value (str | int | float): The date value to be converted. This can be a string representing a date in different formats or a numeric timestamp (integer or float).

    Raises:
        ValueError: When value is a timestamp string and cannot be converted to a 
            datetime object using any of the expected formats.

    Returns:
        datetime.datetime | None: a datetime object, or None if the input value is falsy
    """
    if not value:
        return None
    
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    
    if isinstance(value, (int, float)): # HACK: making this work like the older code... TODO: figure out which messages send int timestamps and how to deal with them (2021-09-22 I think this was the AS:resolved message field ASMT_SESSION_START_DT). - (this looks like an old todo, but keeping it here just in case)
        return datetime.utcfromtimestamp(value / 1000.0)
    
    last_error = None
    for format_string in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, format_string)
        except ValueError as e:
            last_error = e
    raise last_error

def convert_value(value, field_specD):
    """Converts a value to a Pythonic version based on the configured 
    message field spec. 
    
    Converted types include: string, integer (int), number (float), boolean (bool)
    If the type is 'string', then the field spec 'format' is also 
    checked for potential formatting to 'date-time', 'integer', 'number' or 'boolean'.
    If the type is 'boolean', the value is checked against 2 tuples of allowed 
    values and converted to a bool based on a match, else an error is raised
    
    NOTE: if there are multiple types, field_specD.get("type") must have already been converted to a single type

    Args:
        value (any): the value to convert
        field_specD (dict): spec for the field taken from message definitions

    Raises:
        ValueError: In cases when type is 'boolean', but the value does 
            not match any of the allowed boolean values
        NMProgrammingError: When the type defined in the spec is not valid

    Returns:
        any: the converted value, or the value itself if no 'type' was defined
    """
    if value is None: # This makes all types nullable for this function... but the schema validation might intefere with this...
        return None
    
    type_string = field_specD.get("type")
    
    if type_string == "string":
        format_name = field_specD.get("format")
        if format_name == "date-time":
            return convert_date_from_string(value)
        elif format_name in ("integer", "number", "boolean"):
            return convert_value(value, {"type": format_name})
        else:
            return str(value)
    elif type_string in ("integer",):
        return int(value)
    elif type_string == "number":
        return float(value)
    elif type_string in ("boolean",):
        if str(value).lower() in ("y", "yes", "t", "true", "1", 1, "on", "ohyeah"):
            return True
        elif str(value).lower() in ("false", "f", "n", "no", "0", "you kidding?", "not a chance"):
            return False
        else:
            raise ValueError("Unknown boolean type string")
    elif type_string is None:
        return value
    else:
        raise NMProgrammingError("Unknown type string: %s" % type_string)

def try_convert_to_int(value, default=None):
    """Attempts to convert a value to an integer, else returns
    the given default value (defaults to None)
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default