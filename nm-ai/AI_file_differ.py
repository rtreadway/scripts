"""
AI File Differ Script

This script processes AI data queries and generates comprehensive reports including:
1. Excel file diffing for merges and deletions (original functionality)
2. Additional analysis queries for current deletions, new records, and J-to-S transitions
3. Comprehensive markdown reporting

The script connects to a Redshift/PostgreSQL database, runs multiple SQL queries,
and produces both Excel output (for historical tracking) and markdown reports
(for comprehensive analysis).

Key Features:
- Abstracts Excel diffing into reusable functions
- Processes additional queries for enhanced reporting
- Generates markdown reports with executive summaries and detailed analysis
- Maintains backward compatibility with existing Excel workflows

Usage:
    python AI_file_differ.py <env> --infile <path_to_prior_xlsx> [options]
"""

from functools import lru_cache
import argparse
import os
import sys
import datetime
import calendar
import logging

import boto3
import psycopg2
import pandas as pd
from openpyxl import load_workbook
from openpyxl.utils import get_column_letter

# Set up logger
logger = logging.getLogger(__name__)

# Optional SQLAlchemy import - graceful fallback to psycopg2
try:
    import sqlalchemy  # noqa: F401
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False


PARAM_TRANSLATION_TEMPLATE = {
    '/NMSQT/{env_name}/{db_name}/Host': 'host',
    '/NMSQT/{env_name}/{db_name}/Database': 'database',
    '/NMSQT/{env_name}/{db_name}/Port': 'port',
    '/NMSQT/{env_name}/{db_name}/Username': 'user',
    '/NMSQT/{env_name}/{db_name}/Password': 'password',
}

QUERY_TO_SHEET_NAME = {
    "ai_char_diffs": "Character replacements",
    "ai_domestic_trunc": "Truncations",
    "ai_intl_trunc": "Truncations - International"
}

SHEET_FIELD_TRANSLATIONS = {  # TODO: eliminate this by adjusting the queries
    "Character replacements": {
        "ai_code": "AI Code",
        "flag_name": "Attribute",
        "original_value": "Original Value",
        "transformed_value": "Transformed Value",
    },
    "Truncations": {
        "ai_code": "AI Code",
        "sname": "SNAME",
        "flag_name": "Truncated Attribute",
        "original_value": "Original Value",
        "transformed_value": "Value after Truncation",
        "original_len": "Original length",
    },
    "Truncations - International": {
        "field": "Field",
        "ai_code": "Ai Code",
        "full": "Full Name",
        "value_len": "Length",
        "transformed": "Value after Truncation",
    }
}

SHEET_FIELD_TRANSLATIONS_REVERSE = {}
for sheet, mapping in SHEET_FIELD_TRANSLATIONS.items():
    new_internal = {}
    for old_name, new_name in mapping.items():
        new_internal[new_name] = old_name
    SHEET_FIELD_TRANSLATIONS_REVERSE[sheet] = new_internal

SHEET_FIELD_TYPE_CONVERSIONS = {
    "Character replacements": {
        "AI Code": str,
        "Attribute": str,
        "Original Value": str,
        "Transformed Value": str,
    },
    "Truncations": {
        "AI Code": str,
        "SNAME": str,
        "Truncated Attribute": str,
        "Original Value": str,
        "Value after Truncation": str,
        "Original length": int,
    },
    "Truncations - International": {
        "Ai Code": str,
        "Field": str,
        "Full Name": str,
        "Length": int,
        "Value after Truncation": str,
    }
}

class DatabaseConnection:
    """Wrapper class that supports both SQLAlchemy and psycopg2 connections."""
    
    def __init__(self, connection_params, engine_type='auto'):
        self.connection_params = connection_params
        self.requested_engine_type = engine_type
        self.actual_engine_type = None
        self.engine = None
        self.psycopg2_conn = None
        self._initialized = False
    
    def _initialize_connection(self):
        """Initialize the connection on first use."""
        if self._initialized:
            return
            
        if self.requested_engine_type == 'auto':
            # Auto-detect: prefer SQLAlchemy if available
            if SQLALCHEMY_AVAILABLE:
                self._create_sqlalchemy_engine()
            else:
                self._create_psycopg2_connection()
        elif self.requested_engine_type == 'sqlalchemy':
            if not SQLALCHEMY_AVAILABLE:
                raise ImportError("SQLAlchemy requested but not available. Install with: pip install sqlalchemy")
            self._create_sqlalchemy_engine()
        elif self.requested_engine_type == 'psycopg2':
            self._create_psycopg2_connection()
        else:
            raise ValueError(f"Unknown engine_type: {self.requested_engine_type}. Use 'auto', 'sqlalchemy', or 'psycopg2'")
        
        self._initialized = True
    
    def _create_sqlalchemy_engine(self):
        """Create SQLAlchemy engine from connection parameters."""
        if not SQLALCHEMY_AVAILABLE:
            raise ImportError("SQLAlchemy not available")
        
        from sqlalchemy import create_engine, text
        from urllib.parse import quote_plus
        
        host = self.connection_params['host']
        port = self.connection_params['port']
        database = self.connection_params['database']
        user = self.connection_params['user']
        password = quote_plus(self.connection_params['password'])
        
        try:
            # Try sqlalchemy-redshift dialect first (most Redshift-compatible)
            try:
                import sqlalchemy_redshift  # type: ignore[import-not-found]  # noqa: F401
                connection_string = f"redshift+psycopg2://{user}:{password}@{host}:{port}/{database}?sslmode=require"
                logger.info("Using sqlalchemy-redshift dialect for SQLAlchemy")
                
                # Create engine with Redshift-optimized settings
                self.engine = create_engine(
                    connection_string,
                    # Disable server-side cursors which can cause issues with Redshift
                    server_side_cursors=False,
                    # Pool settings for better connection management
                    pool_pre_ping=True,
                    pool_recycle=3600,
                    # Echo SQL for debugging if needed
                    echo=False,
                    # Additional connection args for Redshift compatibility
                    connect_args={
                        'sslmode': 'require'
                    }
                )
                
            except ImportError:
                # Try redshift-connector as second option
                try:
                    import redshift_connector  # type: ignore[import-not-found]  # noqa: F401
                    connection_string = f"redshift+redshift_connector://{user}:{password}@{host}:{port}/{database}"
                    logger.info("Using redshift-connector for SQLAlchemy (sqlalchemy-redshift not available)")
                    
                    # Create engine with Redshift-optimized settings
                    self.engine = create_engine(
                        connection_string,
                        server_side_cursors=False,
                        pool_pre_ping=True,
                        pool_recycle=3600,
                        echo=False
                    )
                    
                except ImportError:
                    # Fall back to postgresql+psycopg2 with Redshift-specific settings
                    connection_string = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}?sslmode=require"
                    logger.info("Using postgresql+psycopg2 for SQLAlchemy (no Redshift-specific dialects available)")
                    
                    # Create a Redshift-compatible custom dialect
                    from sqlalchemy.dialects.postgresql.psycopg2 import PGDialect_psycopg2
                    
                    class RedshiftCompatibleDialect(PGDialect_psycopg2):
                        name = 'redshift_compatible'
                        
                        def _get_server_version_info(self, connection):
                            # Skip server version detection to avoid problematic queries
                            return (8, 4, 0)
                        
                        def do_begin_twophase(self, connection, xid):
                            # Redshift doesn't support two-phase commit
                            pass
                        
                        def do_prepare_twophase(self, connection, xid):
                            # Redshift doesn't support two-phase commit
                            pass
                        
                        def do_commit_twophase(self, connection, xid, is_prepared=True, recover=False):
                            # Redshift doesn't support two-phase commit
                            connection.commit()
                        
                        def do_rollback_twophase(self, connection, xid, is_prepared=True, recover=False):
                            # Redshift doesn't support two-phase commit
                            connection.rollback()
                        
                        def get_isolation_level(self, dbapi_connection):
                            # Return a default isolation level for Redshift
                            return "READ_COMMITTED"
                        
                        def initialize(self, connection):
                            # Skip problematic PostgreSQL initialization queries
                            try:
                                # Call the base Dialect initialize, not the PostgreSQL one
                                super(PGDialect_psycopg2, self).initialize(connection)
                            except Exception:
                                # If that fails, just set basic attributes
                                self.server_version_info = (8, 4, 0)
                                self.default_schema_name = 'public'
                    
                    # Register the custom dialect
                    from sqlalchemy.dialects import registry
                    registry.register("redshift_compatible.psycopg2", "AI_file_differ", "RedshiftCompatibleDialect")
                    
                    # Create engine with custom dialect
                    custom_connection_string = f"redshift_compatible+psycopg2://{user}:{password}@{host}:{port}/{database}?sslmode=require"
                    
                    self.engine = create_engine(
                        custom_connection_string,
                        server_side_cursors=False,
                        pool_pre_ping=False,
                        pool_recycle=3600,
                        echo=False,
                        connect_args={
                            'sslmode': 'require'
                        },
                        execution_options={
                            "postgresql_readonly": False,
                            "postgresql_insert_returning": False
                        }
                    )
                    
                    logger.info("Applied custom Redshift-compatible dialect")
            
            # Test the connection with a simple query
            with self.engine.connect() as conn:
                # Use a simple query that works reliably on Redshift
                result = conn.execute(text("SELECT 1 as test")).fetchone()
                if result and result[0] == 1:
                    logger.info("SQLAlchemy connection test successful")
                else:
                    raise Exception("Connection test failed")
            
            self.actual_engine_type = 'sqlalchemy'
                
        except Exception as e:
            logger.error(f"SQLAlchemy connection failed: {e}")
            logger.info("Falling back to psycopg2...")
            self.engine = None
            # Fall back to psycopg2
            self._create_psycopg2_connection()
    
    def _create_psycopg2_connection(self):
        """Create psycopg2 connection from connection parameters."""
        self.psycopg2_conn = psycopg2.connect(**self.connection_params, sslmode="require")
        self.actual_engine_type = 'psycopg2'
    
    def get_connection_for_pandas(self):
        """Get the appropriate connection object for pandas operations."""
        self._initialize_connection()
        if self.actual_engine_type == 'sqlalchemy' and self.engine is not None:
            # For pandas with SQLAlchemy, we need to return the engine itself
            # pandas will handle creating connections internally
            return self.engine
        else:
            return self.psycopg2_conn
    
    def get_raw_connection(self):
        """Get raw connection for direct SQL execution (DDL, etc.)."""
        self._initialize_connection()
        if self.actual_engine_type == 'sqlalchemy' and self.engine is not None:
            return self.engine.raw_connection()
        else:
            return self.psycopg2_conn
    
    def get_engine_type(self):
        """Return the current engine type being used."""
        self._initialize_connection()
        return self.actual_engine_type

def extract_and_increment_month(filename):
    """Extract month name from filename and bump to the next month name."""
    basename = os.path.basename(filename)
    # normalize to lowercase & replace underscores with spaces just in case
    previous_month = basename.replace('_', ' ').split()[0].strip().title()
    logger.info(f"Previous File Month: {previous_month}")
    try:
        idx = list(calendar.month_name).index(previous_month)
        next_idx = idx % 12 + 1 # wrap around to January if December
        # logger.debug(f"Next Month Index: {next_idx}")
        next_month = calendar.month_name[next_idx]
        return previous_month, next_month
    except ValueError:
        # now = datetime.datetime.now().month
        # logger.warning(f"'{previous_month}' not a valid month name; using {calendar.month_name[now]}")
        # return previous_month, calendar.month_name[now]
        raise ValueError(f"Error: '{previous_month}' not a valid month name")

def get_database_parameters(db_name, env_name):  # Copied from hyperloop project
    """
    Retrieve database parameters from AWS Systems Manager Parameter Store.
    This function formats parameter names based on the provided database name and environment name,
    retrieves the corresponding parameters from AWS SSM Parameter Store, and returns them in a dictionary.
    
    Args:
        db_name (str): The name of the database.
        env_name (str): The name of the environment.
    
    Returns:
        dict: A dictionary where the keys are the translated parameter names and the values are the parameter values retrieved from SSM.
    """
    param_translation = {}
    for k, v in PARAM_TRANSLATION_TEMPLATE.items():
        param_translation[k.format(db_name=db_name, env_name=env_name)] = v
    
    try:
        response = boto3.client('ssm').get_parameters(Names=list(param_translation.keys()), WithDecryption=True)
    except Exception as e:
        logger.error(f"Error fetching parameters: {e}")
        sys.exit(1)
    
    paramsD = {}
    if response['Parameters']:
        logger.info(f"Found {len(response['Parameters'])} parameters for {db_name} in {env_name}")
        # logger.debug("Parameters:", [p['Name'] for p in response['Parameters']])
    else:
        logger.error(f"No parameters found for {db_name} in {env_name}")
        sys.exit(1)
    
    for param_info in response['Parameters']:
        if param_info['Name'] in param_translation:
            paramsD[param_translation[param_info['Name']]] = param_info['Value']
    
    return paramsD

@lru_cache
def get_cornerstone_connection(env_name, engine_type='auto'):  # Copied from hyperloop project
    """
    Establishes a connection to the Cornerstone database.
    
    Args:
        env_name (str): The environment name to fetch the database parameters for.
        engine_type (str): Database engine type - 'auto', 'sqlalchemy', or 'psycopg2'
    
    Returns:
        DatabaseConnection: A connection wrapper object supporting both SQLAlchemy and psycopg2.
    
    Raises:
        Exception: If there is an issue with fetching the database parameters or connecting to the database.
    """
    logger.info("Fetching DB Params")
    paramsD = get_database_parameters("Cornerstone", env_name)
    
    logger.info(f"Connecting to Cornerstone Server at {paramsD['host']}")
    db_conn = DatabaseConnection(paramsD, engine_type)
    logger.info(f"Connected using {db_conn.get_engine_type()} engine")
    
    return db_conn

def run_query(db_conn, sql):
    """Execute a SQL query and return a pandas DataFrame."""
    if isinstance(db_conn, DatabaseConnection):
        # Use our connection wrapper
        if db_conn.get_engine_type() == 'sqlalchemy' and db_conn.engine is not None:
            # For SQLAlchemy 2.x with pandas >= 2.2.2, pass the Engine directly
            # pandas will handle creating connections internally
            return pd.read_sql(sql, con=db_conn.engine)
        else:
            # For psycopg2 connections, get the actual connection
            raw_conn = db_conn.get_raw_connection()
            if raw_conn is not None:
                import warnings
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", message="pandas only supports SQLAlchemy connectable")
                    return pd.read_sql(sql, raw_conn)  # type: ignore[arg-type]
            else:
                raise RuntimeError("Failed to get psycopg2 connection")
    else:
        # Fallback for legacy psycopg2 connections
        import warnings
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="pandas only supports SQLAlchemy connectable")
            return pd.read_sql(sql, db_conn)  # type: ignore[arg-type]

def execute_sql(db_conn, sql):
    """Execute a SQL statement that doesn't return results (DDL, INSERT, etc.)"""
    if isinstance(db_conn, DatabaseConnection):
        # Use our connection wrapper
        if db_conn.get_engine_type() == 'sqlalchemy' and db_conn.engine is not None:
            # For SQLAlchemy 2.x, use Engine.begin() and exec_driver_sql()
            with db_conn.engine.begin() as conn:
                conn.exec_driver_sql(sql)
                # No need for explicit commit() - begin() handles it automatically
        else:
            # For psycopg2
            raw_conn = db_conn.get_raw_connection()
            if raw_conn is not None:
                cursor = raw_conn.cursor()
                try:
                    cursor.execute(sql)
                    raw_conn.commit()
                finally:
                    cursor.close()
    else:
        # Fallback for legacy psycopg2 connections
        cursor = db_conn.cursor()
        try:
            cursor.execute(sql)
            db_conn.commit()
        finally:
            cursor.close()
    return None

def compare_sheets(old_df, new_df, key_cols):
    # mark new vs deleted
    merged = new_df.merge(old_df, on=key_cols, how='outer', 
                          indicator=True, suffixes=('_new','_old'))
    added   = merged[merged["_merge"]=="left_only"].drop(columns=["_merge"])
    removed = merged[merged["_merge"]=="right_only"].drop(columns=["_merge"])
    # for rows present in both, compare cell-by-cell
    both = merged[merged["_merge"]=="both"]
    diffs = []
    for col in new_df.columns:
        if col in key_cols: 
            continue
        # where old vs new differ
        mask = both[f"{col}_new"] != both[f"{col}_old"]
        if mask.any():
            tmp = both.loc[mask, key_cols + [f"{col}_old", f"{col}_new"]]
            diffs.append((col, tmp))
    return added, removed, diffs

def prep_queries_from_sql_files(query_file_path, parameter_overrideD=None):
    """Prepare queries from SQL files
    
    This function will read all SQL files in a directory, extract metadata from the files,
    remove comments, replace placeholders, and return a list of tuples with the filename, notes,
    and the SQL queries.
    
    NOTE: The filename = the query name TODO: eventually change this to map to sheet names to simplify the code
    """
    output = []
    try:
        for sql_file in os.listdir(query_file_path):
            if not sql_file.endswith(".sql"):
                continue
            full_filepath = os.path.join(query_file_path, sql_file)
            sql_filename = sql_file.removesuffix(".sql")
            
            with open(full_filepath, 'r') as f:
                try:
                    full_sql = f.read().format(**parameter_overrideD) if parameter_overrideD else f.read()
                except KeyError as ke:
                    logger.error(f"Missing parameter {ke} in file {sql_file}")
                    logger.error(f"Available parameters: {list(parameter_overrideD.keys()) if parameter_overrideD else 'None'}")
                    raise
                
                # metadata = extract_sql_file_metadata(full_sql)
            output.append((sql_filename, full_sql))
    except Exception as e:
        logger.error(f"Error preparing queries: {e}")
        raise
    return output

def get_clean_header_from_worksheet(ws):
    header = []
    for cell in ws[1]:
        v = cell.value
        if isinstance(v, str):
            v = v.strip()
            if not v:
                continue
        if v is None:
            continue
        header.append(v)
    
    return header

def populate_deletions_sheet(wb, additional_results, verbose=False):
    """Populate the Deletions sheet with current deletions data."""
    if 'ai_current_deletions' not in additional_results:
        if verbose:
            logger.info("No 'ai_current_deletions' key found in additional_results")
            logger.info(f"Available keys: {list(additional_results.keys())}")
        return
    
    deletions_df = additional_results['ai_current_deletions']
    
    if deletions_df.empty:
        if verbose:
            logger.info("Current deletions dataframe is empty")
        return
    
    if verbose:
        logger.info(f"Found {len(deletions_df)} deletion records")
        logger.info(f"Deletions DataFrame columns: {list(deletions_df.columns)}")
        logger.info(f"Sample deletion record: {deletions_df.iloc[0].to_dict() if len(deletions_df) > 0 else 'No records'}")
    
    # Check if Deletions sheet exists
    if "Deletions" not in wb.sheetnames:
        if verbose:
            logger.warning("Warning: 'Deletions' sheet not found in workbook")
            logger.info(f"Available sheets: {wb.sheetnames}")
        return
    
    deletions_ws = wb["Deletions"]
    
    # Check if row 1 is a title and row 2 contains headers
    row1_values = [cell.value for cell in deletions_ws[1] if cell.value is not None]
    row2_values = [cell.value for cell in deletions_ws[2] if cell.value is not None]
    
    if verbose:
        logger.info(f"Row 1 content: {row1_values}")
        logger.info(f"Row 2 content: {row2_values}")
    
    # Determine if we should use row 2 as headers instead of row 1
    if len(row1_values) == 1 and len(row2_values) > 1:
        if verbose:
            logger.info("Detected title row in row 1, using row 2 as headers")
        header_row = 2
        data_start_row = 3
        # Get headers from row 2
        header = []
        for cell in deletions_ws[2]:
            v = cell.value
            if isinstance(v, str):
                v = v.strip()
                if not v:
                    continue
            if v is None:
                continue
            header.append(v)
    else:
        if verbose:
            logger.info("Using row 1 as headers")
        header_row = 1
        data_start_row = 2
        header = get_clean_header_from_worksheet(deletions_ws)
    
    if verbose:
        logger.info(f"Using headers from row {header_row}: {header}")
    
    # Find the column indices for AI Code and School Name
    ai_code_col = None
    school_name_col = None
    reason_col = None
    
    for idx, col in enumerate(header, 1):
        if col == "AI Code":
            ai_code_col = idx
        elif col == "School Name":
            school_name_col = idx
        elif col == "Reason for Deletion":
            reason_col = idx
    
    if verbose:
        logger.info(f"Column mapping: AI Code={ai_code_col}, School Name={school_name_col}, Reason={reason_col}")
    
    if ai_code_col is None or school_name_col is None:
        if verbose:
            logger.warning("Required columns 'AI Code' or 'School Name' not found in Deletions sheet")
            logger.info(f"Available columns: {header}")
        return
    
    # Clear existing data (keep title and header rows)
    if deletions_ws.max_row > data_start_row - 1:
        deletions_ws.delete_rows(data_start_row, deletions_ws.max_row - data_start_row + 1)
    
    # Populate with current deletions data starting from the appropriate row
    records_written = 0
    for row_idx, (_, row) in enumerate(deletions_df.iterrows(), start=data_start_row):
        # AI Code - try multiple possible column names
        ai_code = ''
        for possible_col in ['ai_code', 'AI_CODE', 'ai_cd', 'AI_CD']:
            if possible_col in row and pd.notna(row[possible_col]):
                ai_code = str(row[possible_col])
                break
        
        if ai_code:
            deletions_ws.cell(row=row_idx, column=ai_code_col, value=ai_code)
        
        # School Name - try multiple possible column names
        school_name = ''
        for possible_col in ['name', 'NAME', 'school_name', 'SCHOOL_NAME', 'ai_name', 'AI_NAME']:
            if possible_col in row and pd.notna(row[possible_col]):
                school_name = str(row[possible_col])
                break
        
        if school_name:
            deletions_ws.cell(row=row_idx, column=school_name_col, value=school_name)
        
        # Reason for Deletion - keep blank as requested
        if reason_col:
            deletions_ws.cell(row=row_idx, column=reason_col, value="")
        
        records_written += 1
        
        # Debug first few records
        if verbose and row_idx <= data_start_row + 2:
            print(f"Row {row_idx}: AI Code='{ai_code}', School Name='{school_name}'")
            if row_idx == data_start_row:  # Only show columns for first data row
                print(f"  Available columns in this row: {list(row.index)}")
    
    if verbose:
        print(f"Populated Deletions sheet with {records_written} records starting from row {data_start_row}")


def process_excel_diff(conn, args, target_month, old_sheets, wb, additional_results=None, email_statsD=None):
    """Process Excel diffing for merges and deletions queries."""
    diff_report = []
    detail_dfs = []  # collect DataFrames for verbose output processing
    if additional_results is None:
        additional_results = {}
    if email_statsD is None:
        email_statsD = {}
    
    MERGES_DELETIONS_DIFF_QUERY_ALLOWS = ['ai_domestic_trunc', 'ai_intl_trunc', 'ai_char_diffs']
    
    # Get queries for Excel diffing
    QUERIES = prep_queries_from_sql_files("ai_diff_queries")
    QUERIES_DICT = {}
    
    for k, v in QUERIES:
        if k in MERGES_DELETIONS_DIFF_QUERY_ALLOWS:
            if args.verbose:
                print(f"Running Excel diff query for {k}")
            QUERIES_DICT[k] = run_query(conn, v)
    
    if args.verbose:
        print("Excel diff queries executed.")
        print("QUERIES_DICT:")
        for k, v in QUERIES_DICT.items():
            print(f"  {k}: {v.shape}")
    
    # Compare with old data and write new Excel file
    if args.verbose:
        print("Comparing new data with old data...")
    
    for sql_name, new_df in QUERIES_DICT.items():
        actual_name = QUERY_TO_SHEET_NAME.get(sql_name, sql_name)
        if not actual_name or actual_name not in wb.sheetnames:
            raise KeyError(f"Sheet '{actual_name}' not found in {args.infile}")

        # fetch the old DataFrame by the same sheet name
        old_df = old_sheets.get(actual_name, pd.DataFrame())

        # apply any sheet-specific header translations
        field_map = SHEET_FIELD_TRANSLATIONS.get(actual_name, {})
        if field_map and args.verbose:
            print(f"Applying column‐name mapping for '{actual_name}': {field_map}")
        if field_map:
            new_df = new_df.rename(columns=field_map)
        
        # apply sheet‐specific type conversions to both old_df & new_df
        type_map = SHEET_FIELD_TYPE_CONVERSIONS.get(actual_name, {})
        for df in (old_df, new_df):
            for col, dtype in type_map.items():
                if col in df.columns:
                    # convert floats→ints (e.g. Length) or enforce str
                    df[col] = df[col].astype(dtype)

        # pull the header row from the template sheet
        ws = wb[actual_name]
        header = get_clean_header_from_worksheet(ws)

        # enforce that columns now match exactly
        if list(new_df.columns) != header:
            raise ValueError(
                f"Column mismatch in '{actual_name}':\n"
                f"  expected {header}\n"
                f"  got      {list(new_df.columns)}"
            )
            
        if actual_name == "Character replacements":
            key_cols = ["AI Code", "Attribute"]
        elif actual_name == "Truncations":
            key_cols = ["AI Code", "Truncated Attribute"]
        elif actual_name == "Truncations - International":
            key_cols = ["Ai Code", "Field"]
        else:
            # fallback: first column as key
            key_cols = [header[0]]
        
        # normalize key‐column types to string on both old & new
        for df in (old_df, new_df):
            for k in key_cols:
                if k in df.columns:
                    df[k] = df[k].astype(str)

        # THE DIFFING
        if not old_df.empty:
            added, removed, diffs = compare_sheets(old_df, new_df, key_cols)
            
            changed_keys = set()
            for _, dfchg in diffs:
                for _, row in dfchg[key_cols].iterrows():
                    changed_keys.add(tuple(row[col] for col in key_cols))
            row_changes = len(changed_keys)
            
            if args.detail_report:
                 if not added.empty:
                     # For ADDED rows, only keep columns ending with '_new' and key columns
                     added_clean = added.copy()
                     cols_to_keep = [col for col in added_clean.columns if col.endswith('_new') or col in key_cols]
                     added_clean = added_clean[cols_to_keep]
                     # Remove '_new' suffix for cleaner display
                     added_clean.columns = [col.replace('_new', '') if col.endswith('_new') else col for col in added_clean.columns]
                     
                     # Sort by AI Code and Field for international truncations
                     if actual_name == "Truncations - International" and 'Ai Code' in added_clean.columns and 'Field' in added_clean.columns:
                         added_clean = added_clean.sort_values(['Ai Code', 'Field'])
                     
                     detail_dfs.append((f"{actual_name}_ADDED", added_clean))
                     if args.verbose:
                         print(f"\n[{actual_name}] ADDED ({len(added_clean)} rows):")
                         print(added_clean.to_string(index=False))
                 if not removed.empty:
                     # For REMOVED rows, only keep columns ending with '_old' and key columns
                     removed_clean = removed.copy()
                     cols_to_keep = [col for col in removed_clean.columns if col.endswith('_old') or col in key_cols]
                     removed_clean = removed_clean[cols_to_keep]
                     # Remove '_old' suffix for cleaner display
                     removed_clean.columns = [col.replace('_old', '') if col.endswith('_old') else col for col in removed_clean.columns]
                     
                     # Sort by AI Code and Field for international truncations
                     if actual_name == "Truncations - International" and 'Ai Code' in removed_clean.columns and 'Field' in removed_clean.columns:
                         removed_clean = removed_clean.sort_values(['Ai Code', 'Field'])
                     
                     detail_dfs.append((f"{actual_name}_REMOVED", removed_clean))
                     if args.verbose:
                         print(f"\n[{actual_name}] REMOVED ({len(removed_clean)} rows):")
                         print(removed_clean.to_string(index=False))
                 for col, diff_df in diffs:
                     # Sort by AI Code and Field for international truncations changes
                     if actual_name == "Truncations - International" and 'Ai Code' in diff_df.columns and 'Field' in diff_df.columns:
                         diff_df = diff_df.sort_values(['Ai Code', 'Field'])
                     
                     detail_dfs.append((f"{actual_name}_CHG_{col}", diff_df))
                     if args.verbose:
                         print(f"\n[{actual_name}] CHANGES in column '{col}' ({len(diff_df)} rows):")
                         print(diff_df.to_string(index=False))
            print(f"  + new rows: {len(added)}  - removed rows: {len(removed)}  * row-changes: {row_changes}")
            diff_report.append({
                "sheet": actual_name,
                "added": len(added),
                "removed": len(removed),
                "row_changes": row_changes
            })
            if sql_name == 'ai_domestic_trunc':
                email_statsD['ai_domestic_net'] = len(added) - len(removed)
                email_statsD['ai_domestic_added'] = len(added)
                email_statsD['ai_domestic_removed'] = len(removed)
                email_statsD['ai_domestic_row_changes'] = row_changes
                email_statsD['prev_total_domestic_diffs'] = len(old_df)
                email_statsD['total_ai_domestic_trunc'] = len(new_df)
            
            elif sql_name == 'ai_char_diffs':
                email_statsD['ai_char_diffs_net'] = len(added) - len(removed)
                email_statsD['ai_char_diffs_added'] = len(added)
                email_statsD['ai_char_diffs_removed'] = len(removed)
                email_statsD['ai_char_diffs_row_changes'] = row_changes
                email_statsD['prev_total_char_diffs'] = len(old_df)
                email_statsD['total_ai_char_diffs'] = len(new_df)
            
            elif sql_name == 'ai_intl_trunc':
                email_statsD['ai_intl_net'] = len(added) - len(removed)
                email_statsD['ai_intl_added'] = len(added)
                email_statsD['ai_intl_removed'] = len(removed)
                email_statsD['ai_intl_row_changes'] = row_changes
                email_statsD['prev_total_intl_diffs'] = len(old_df)
                email_statsD['total_ai_intl_trunc'] = len(new_df)
            else:
                print("WARNING: Unrecognized SQL name")
        else:
            print(f"  No existing data to compare in '{actual_name}', treating all {len(new_df)} as new.")
            diff_report.append({
                "sheet": actual_name,
                "added": len(new_df),
                "removed": 0,
                "row_changes": 0
            })

        # clear old data rows (leave row 1 = header & style intact)
        if ws.max_row > 1:
            ws.delete_rows(2, ws.max_row - 1)

        # write new_df values back in, starting at row 2
        for r, row in enumerate(new_df.itertuples(index=False), start=2):
            for c, value in enumerate(row, start=1):
                ws.cell(row=r, column=c, value=value)

    # Populate Deletions sheet if additional_results provided
    if additional_results:
        populate_deletions_sheet(wb, additional_results, args.verbose)

    # save under new filename
    outname = f"{target_month} NMSC AI Merges and Deletions.xlsx"
    outpath = os.path.join(args.outdir, outname)
    wb.save(outpath)
    logger.info(f"New workbook saved to {outpath}")
    
    if args.detail_report and detail_dfs:
        detail_path = os.path.join(args.outdir, f"diff_details_{target_month}.xlsx")
        with pd.ExcelWriter(detail_path, engine="openpyxl") as det_writer:
            for sheet_name, df in detail_dfs:
                # ensure sheet name ≤ 31 chars
                safe_name = sheet_name[:31]
                df.to_excel(det_writer, sheet_name=safe_name, index=False)
                
                # grab the sheet and freeze the top row
                ws = det_writer.book[safe_name]
                ws.freeze_panes = "A2"
                
                # optional: auto‐column‐width
                for idx, col in enumerate(df.columns, 1):
                    max_len = max(
                        df[col].astype(str).map(len).max(),
                        len(col)
                    ) + 2
                    ws.column_dimensions[get_column_letter(idx)].width = max_len
        logger.info(f"Detailed diff workbook saved to {detail_path}")

    return diff_report, detail_dfs

def iterate_queries(conn, args, query_dir, return_result=True, query_filterL=None, parameter_overrideD=None):
    """Iterate through and execute queries from SQL files in a directory."""
    prepped_queries = prep_queries_from_sql_files(query_dir, parameter_overrideD)
    results = {}
    
    for k, v in prepped_queries:
        if query_filterL and k not in query_filterL:
            if args.verbose:
                logger.info(f"Skipping query for {k}")
            continue
        if args.verbose:
            logger.info(f"Running query for {k}")
        if return_result:
            results[k] = run_query(conn, v)
            if args.verbose:
                logger.info(f"  {k}: {results[k].shape}")
        else:
            execute_sql(conn, v)
            if args.verbose:
                logger.info(f"  {k}: executed")
    
    return results

def export_stats_for_email(additional_results, output_path=None):
    """Export stats in JSON format for email template generation."""
    stats = {}
    
    # Extract counts from additional results
    for query_name, result_df in additional_results.items():
        name = query_name.lower()
        val = (result_df.iloc[0, 0] if not result_df.empty else 0)

        # Handle specific keys first to avoid 'account' matching 'count'
        if 'deletions_count' in name:
            stats['ai_current_deletions_count'] = str(val)
        elif 'new_count' in name:
            stats['ai_current_new_count'] = str(val)
        elif 'changes_count' in name:
            stats['ai_current_changes_count'] = str(val)
        elif 'total_current_records' in name:
            stats['ai_total_current_records'] = str(val)
        elif not result_df.empty:
            # Detail fallbacks by name patterns
            if 'j_to_s_detail' in name:
                stats['j_to_s_switches'] = str(len(result_df)) or '0'
            elif 's_to_j_detail' in name:
                stats['s_to_j_switches'] = str(len(result_df)) or '0'
    
    # Add current date
    # stats['current_ai_daily'] = datetime.datetime.now().strftime("%Y-%m-%d")
    
    # Export to JSON
    # import json
    # with open(output_path, 'w') as f:
    #     json.dump(stats, f, indent=2)
    
    return stats


def generate_markdown_report(target_month, diff_report, additional_results, args, email_statsD=None):
    """Generate a comprehensive markdown report."""
    report_filename = f"AI_Report_{target_month.replace(' ', '_')}.md"
    report_path = os.path.join(args.outdir, report_filename)
    with open(report_path, 'w') as f:
        # Header
        f.write(f"# AI File Differ Report - {target_month}\n\n")
        f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Environment: {args.env}\n\n")

        # Executive Summary
        f.write("## Executive Summary\n\n")

        # Optional stats snapshot
        if email_statsD:
            f.write("### Current Stats Snapshot\n\n")
            def _get(k, default='0'):
                try:
                    v = email_statsD.get(k, default)
                    return f"{int(v):,}" if str(v).isdigit() else str(v)
                except Exception:
                    return str(email_statsD.get(k, default))
            f.write(f"- Total current records: {_get('ai_total_current_records')}\n")
            f.write(f"- New this run: {_get('ai_current_new_count')}\n")
            f.write(f"- Deletions this run: {_get('ai_current_deletions_count')}\n")
            f.write(f"- Field-level changes: {_get('ai_current_changes_count')}\n")
            if 's_to_j_switches' in email_statsD or 'j_to_s_switches' in email_statsD:
                f.write(f"- S→J switches: {_get('s_to_j_switches')}\n")
                f.write(f"- J→S switches: {_get('j_to_s_switches')}\n")
            f.write("\n")

        # Excel Diff Summary
        f.write("### Excel File Changes Summary\n\n")
        if diff_report:
            total_added = sum(r['added'] for r in diff_report)
            total_removed = sum(r['removed'] for r in diff_report)
            total_changed = sum(r['row_changes'] for r in diff_report)

            f.write(f"- **Total Rows Added**: {total_added:,}\n")
            f.write(f"- **Total Rows Removed**: {total_removed:,}\n")
            f.write(f"- **Total Rows Changed**: {total_changed:,}\n\n")

            f.write("| Sheet | Added | Removed | Changed |\n")
            f.write("|-------|-------|---------|----------|\n")
            for report in diff_report:
                f.write(f"| {report['sheet']} | {report['added']:,} | {report['removed']:,} | {report['row_changes']:,} |\n")

        f.write("\n---\n\n")

        # Detailed Sections
        f.write("## Detailed Analysis\n\n")

        # AI Current Deletions List
        if 'ai_current_deletions' in additional_results and not additional_results['ai_current_deletions'].empty:
            deletions_df = additional_results['ai_current_deletions']
            f.write("### AI Current Deletions\n\n")
            f.write(f"Total deletions: {len(deletions_df):,}\n\n")

            if len(deletions_df) <= 100:  # Show all if reasonable number
                f.write("| AI Code | AI | Name | Address Line 1 | City | Country |\n")
                f.write("|---------|----|----|----------------|------|----------|\n")
                for _, row in deletions_df.iterrows():
                    ai_code = str(row.get('ai_code', row.get('AI_CODE', 'N/A')))
                    ai_name = str(row.get('ai', 'N/A'))
                    name = str(row.get('name', 'N/A'))
                    address = str(row.get('pn_address_line1', 'N/A'))
                    city = str(row.get('pn_address_city', 'N/A'))
                    country = str(row.get('pn_country', 'N/A'))
                    f.write(f"| {ai_code} | {ai_name} | {name} | {address} | {city} | {country} |\n")
            else:
                f.write("*Note: Too many deletions to display in full. See detailed Excel report.*\n")
                # Show first 20 as sample
                f.write("\n**Sample (first 20):**\n\n")
                f.write("| AI Code | AI | Name | Address Line 1 | City | Country |\n")
                f.write("|---------|----|----|----------------|------|----------|\n")
                for _, row in deletions_df.head(20).iterrows():
                    ai_code = str(row.get('ai_code', row.get('AI_CODE', 'N/A')))
                    ai_name = str(row.get('ai', 'N/A'))
                    name = str(row.get('name', 'N/A'))
                    address = str(row.get('pn_address_line1', 'N/A'))
                    city = str(row.get('pn_address_city', 'N/A'))
                    country = str(row.get('pn_country', 'N/A'))
                    f.write(f"| {ai_code} | {ai_name} | {name} | {address} | {city} | {country} |\n")
            f.write("\n")

        # AI J to S School Level Details
        if 'ai_j_to_s_detail' in additional_results:
            jtos_df = additional_results['ai_j_to_s_detail']
            f.write("### AI J to S School Level Details\n\n")

            if jtos_df.empty:
                f.write("**No J to S transitions found in this period.**\n\n")
            else:
                f.write(f"Total AI codes with J to S transitions: {len(jtos_df):,}\n\n")

                if len(jtos_df) <= 200:  # Show all if reasonable number
                    f.write("| AI Code | Name | Address Line 1 | City | Country |\n")
                    f.write("|---------|------|----------------|------|----------|\n")
                    for _, row in jtos_df.iterrows():
                        ai_code = str(row.get('ai_code', 'N/A'))
                        name = str(row.get('name', 'N/A'))
                        address = str(row.get('pn_address_line1', 'N/A'))
                        city = str(row.get('pn_address_city', 'N/A'))
                        country = str(row.get('pn_country', 'N/A'))
                        f.write(f"| {ai_code} | {name} | {address} | {city} | {country} |\n")
                else:
                    f.write("*Note: Too many records to display in full. See detailed Excel report.*\n")
                    # Show first 50 as sample
                    f.write("\n**Sample (first 50):**\n\n")
                    f.write("| AI Code | Name | Address Line 1 | City | Country |\n")
                    f.write("|---------|------|----------------|------|----------|\n")
                    for _, row in jtos_df.head(50).iterrows():
                        ai_code = str(row.get('ai_code', 'N/A'))
                        name = str(row.get('name', 'N/A'))
                        address = str(row.get('pn_address_line1', 'N/A'))
                        city = str(row.get('pn_address_city', 'N/A'))
                        country = str(row.get('pn_country', 'N/A'))
                        f.write(f"| {ai_code} | {name} | {address} | {city} | {country} |\n")
            f.write("\n")

        # AI S to J School Level Details
        if 'ai_s_to_j_detail' in additional_results:
            stoj_df = additional_results['ai_s_to_j_detail']
            f.write("### AI S to J School Level Details\n\n")

            if stoj_df.empty:
                f.write("**No S to J transitions found in this period.**\n\n")
            else:
                f.write(f"Total AI codes with S to J transitions: {len(stoj_df):,}\n\n")

                if len(stoj_df) <= 200:  # Show all if reasonable number
                    f.write("| AI Code | Name | Address Line 1 | City | Country |\n")
                    f.write("|---------|------|----------------|------|----------|\n")
                    for _, row in stoj_df.iterrows():
                        ai_code = str(row.get('ai_code', 'N/A'))
                        name = str(row.get('name', 'N/A'))
                        address = str(row.get('pn_address_line1', 'N/A'))
                        city = str(row.get('pn_address_city', 'N/A'))
                        country = str(row.get('pn_country', 'N/A'))
                        f.write(f"| {ai_code} | {name} | {address} | {city} | {country} |\n")
                else:
                    f.write("*Note: Too many records to display in full. See detailed Excel report.*\n")
                    # Show first 50 as sample
                    f.write("\n**Sample (first 50):**\n\n")
                    f.write("| AI Code | Name | Address Line 1 | City | Country |\n")
                    f.write("|---------|------|----------------|------|----------|\n")
                    for _, row in stoj_df.head(50).iterrows():
                        ai_code = str(row.get('ai_code', 'N/A'))
                        name = str(row.get('name', 'N/A'))
                        address = str(row.get('pn_address_line1', 'N/A'))
                        city = str(row.get('pn_address_city', 'N/A'))
                        country = str(row.get('pn_country', 'N/A'))
                        f.write(f"| {ai_code} | {name} | {address} | {city} | {country} |\n")
            f.write("\n")

        # Technical Details
        f.write("## Technical Details\n\n")
        f.write(f"- **Input File**: {args.infile}\n")
        f.write(f"- **Output Directory**: {args.outdir}\n")
        f.write(f"- **AWS Profile**: {args.profile}\n")
        f.write(f"- **Verbose Mode**: {args.verbose}\n")
        f.write(f"- **Detail Report**: {args.detail_report}\n")
        f.write(f"- **Database Engine**: {args.engine}\n\n")

        # Query Information
        f.write("### Queries Executed\n\n")
        f.write("**Excel Diff Queries:**\n")
        f.write("- ai_domestic_trunc\n")
        f.write("- ai_intl_trunc\n")
        f.write("- ai_char_diffs\n\n")

        f.write("**Additional Analysis Queries:**\n")
        for query_name in additional_results.keys():
            f.write(f"- {query_name}\n")

        f.write("\n---\n\n*Report generated by AI File Differ script*\n")

    print(f"Markdown report saved to {report_path}")
    return report_path


def main():
    p = argparse.ArgumentParser(description="Run monthly Redshift queries and diff against prior XLSX")
    p.add_argument("env", default="qa", help="Environment name for DB connection (e.g. prod, staging)")
    p.add_argument("--admin-year", default=2024, help="Admin year for schema names (e.g. 2024)")
    p.add_argument("--month", help="YYYY-MM string for this run (e.g. 2025-06)")
    p.add_argument("--infile", required=True, help="Path to prior-data.xlsx")
    p.add_argument("--outdir", default=".", help="Where to write new file and diff report")
    p.add_argument("--profile", "-p", default="default", help="AWS profile name for SSM access")
    p.add_argument("--verbose", "-v", action="store_true", help="Print detailed console output during processing")
    p.add_argument("--detail-report", "-d", action="store_true", help="Generate detailed Excel diff report with separate sheets for added/removed/changed rows")
    p.add_argument("--engine", choices=['auto', 'sqlalchemy', 'psycopg2'], default='auto', 
                   help="Database engine type: 'auto' (prefer SQLAlchemy, fallback to psycopg2), 'sqlalchemy', or 'psycopg2'")
    p.add_argument("--email-template", help="Path to .msg email template to populate with collected stats")
    p.add_argument("--email-output", help="Output .eml path (optional)")
    args =  p.parse_args()
    
    # 0) Setup 
    boto3.setup_default_session(profile_name=args.profile)
    conn = get_cornerstone_connection(args.env, args.engine)
    
    if args.verbose:
        logger.info(f"Using {conn.get_engine_type()} database engine")
    
    email_stats = {
        'current_year': '',
        'previous_mo': '',
        'current_mo': '',
        'current_ai_daily': '',
        'previous_ai_customer': '',
        
        'ai_current_deletions_count': '',
        'ai_current_new_count': '',
        'ai_current_changes_count': '',
        'ai_total_current_records': '',
        
        'ai_char_diffs_net': '',
        'ai_char_diffs_added': '',
        'ai_char_diffs_removed': '',
        'ai_char_diffs_row_changes': '',
        'prev_total_char_diffs': '',
        'total_ai_char_diffs': '',
        
        'ai_domestic_net': '',
        'ai_domestic_added': '',
        'ai_domestic_removed': '',
        'ai_domestic_row_changes': '',
        'prev_total_domestic_diffs': '',
        'total_ai_domestic_trunc': '',
        
        'ai_intl_net': '',
        'ai_intl_removed': '',
        'ai_intl_added': '',
        'ai_intl_row_changes': '',
        'prev_total_intl_diffs': '',
        'total_ai_intl_trunc': '',
        
        's_to_j_switches': '',
        'j_to_s_switches': '',
        
        'historic_schema_yearly': '',
        'current_schema_yearly': '',
        'historic_schema_all': '',
        'current_schema_all': '',
    }
    
    if args.env != 'prod':
        email_stats['current_schema_yearly'] = f"team_rp__nm_current_{args.admin_year}_{args.env}"
        email_stats['historic_schema_yearly'] = f"team_rp__nm_historic_{args.admin_year}_{args.env}"
        email_stats['current_schema_all'] = f"team_rp__nm_current_all_{args.env}"
        email_stats['historic_schema_all'] = f"team_rp__nm_historic_all_{args.env}"
    else:
        email_stats['current_schema_yearly'] = f"team_rp__nm_current_{args.admin_year}"
        email_stats['historic_schema_yearly'] = f"team_rp__nm_historic_{args.admin_year}"
        email_stats['current_schema_all'] = "team_rp__nm_current_all"
        email_stats['historic_schema_all'] = "team_rp__nm_historic_all"
    
    # 1) Prep existing xlsx file
    if args.month:
        target_month = args.month
        email_stats['current_mo'] = target_month
        if args.verbose:
            logger.info(f"Using manually specified month: {target_month}")
    else:
        previous_month, target_month = extract_and_increment_month(args.infile)
        email_stats['current_mo'] = target_month
        email_stats['previous_mo'] = previous_month
        if args.verbose:
            logger.info(f"Auto-incremented month from input filename: {target_month}")
    email_stats['current_year'] = str(datetime.datetime.now().year)
    
    if os.path.exists(args.infile):
        old_sheets = pd.read_excel(args.infile, sheet_name=None, dtype=str)
        # Clean up old sheets: strip whitespace from column names and string columns
        for df in old_sheets.values():
            df.columns = df.columns.str.strip()
            for c in df.select_dtypes(include="object"):
                df[c] = df[c].str.strip()
        if args.verbose:
            logger.info(f"Loaded existing workbook with {len(old_sheets)} sheets")
    else:
        raise FileNotFoundError(f"Input file {args.infile} does not exist.")

    # 2) Get preparatory data for queries
    if args.verbose:
        logger.info("Getting necessary data from prep queries...")
    PREP_QUERIES = {
        # "previous_ai_customer": "SELECT max(filename) as run_id FROM team_rp__nm_historic_2024.ai_customer", # Non-current year previous for admin year transition month (sept-oct)
        # "previous_ai_customer": "SELECT '2025-09-24T17_01-docker' as run_id",
        "previous_ai_customer": "SELECT max(filename) as run_id FROM {historic_schema_yearly}.ai_customer",
        "current_ai_daily": "SELECT max(run_id) as run_id FROM {historic_schema_yearly}.ai_daily",
    }
    
    for k, v in PREP_QUERIES.items():
        v = v.format(**email_stats)
        if args.verbose:
            logger.info(f"Running query for {k}: {v}")
        PREP_QUERIES[k] = run_query(conn, v).iloc[0]['run_id'].strip()
    email_stats['current_ai_daily'] = PREP_QUERIES['current_ai_daily']
    email_stats['previous_ai_customer'] = PREP_QUERIES['previous_ai_customer']
    
    if args.verbose:
        logger.info("Prepared Queries:", PREP_QUERIES)
    
    # 3) Create temp tables
    if args.verbose:
        logger.info("Creating temporary tables...")
    iterate_queries(conn, args, "ai_diff_temp_tables", return_result=False, parameter_overrideD=email_stats)
    if args.verbose:
        logger.info("Temporary tables created.")
    
    if args.verbose:
        logger.info("Creating secondary temporary tables...")
    iterate_queries(conn, args, "ai_secondary_temp_tables", return_result=False, parameter_overrideD=email_stats)
    if args.verbose:
        logger.info("Secondary temporary tables created.")

    # 4) Process additional queries for comprehensive reporting
    MAIN_QUERIES = [
        'ai_total_current_records',
        'ai_current_changes_count',
        'ai_current_deletions_count',
        'ai_current_new_count', 
        'ai_current_deletions',
        'ai_j_to_s_detail',
        'ai_s_to_j_detail'
    ]
    additional_results = iterate_queries(conn, args, "ai_diff_queries", return_result=True, query_filterL=MAIN_QUERIES)
    
    # 5) Process Excel diffing (original functionality) and populate Deletions sheet
    wb = load_workbook(args.infile)  # preserves styling, column widths, etc.
    diff_report, detail_dfs = process_excel_diff(conn, args, target_month, old_sheets, wb, additional_results, email_stats)
    
    # 6) Export stats first so markdown can include them
    additional_query_stats = export_stats_for_email(additional_results)
    email_stats.update(additional_query_stats)

    # 7) Generate comprehensive markdown report (includes stats snapshot)
    report_path = generate_markdown_report(target_month, diff_report, additional_results, args, email_statsD=email_stats)
    
    logger.info("=== PRINTING EMAIL STATS ===")
    from pprint import pp
    # for key, value in email_stats.items():
    #     logger.info(f"{key}: {value}")
    pp(email_stats)
    logger.info("============================")

    # Optional email generation
    if args.email_template:
        logger.info("GENERATING STATS EMAIL")
        try:
            # If user provided an explicit file path, we'll pass it through; otherwise pass the outdir to derive from subject
            email_out = args.email_output or args.outdir
            from AI_email_generator import generate_ai_email_from_stats  # type: ignore[attr-defined]
            final_email_path = generate_ai_email_from_stats(args.email_template, email_stats, email_out)
            logger.info(f"Email generated at: {final_email_path}")
        except Exception as e:
            logger.error(f"Failed to generate email: {e}")

    # 8) Final summary to console
    logger.info("=== DIFF SUMMARY ===")
    if diff_report:
        logger.info("\n" + pd.DataFrame(diff_report).to_string(index=False))
    
    logger.info("=== ADDITIONAL STATS ===")
    for query_name, result_df in additional_results.items():
        if 'count' in query_name.lower():
            count_val = result_df.iloc[0, 0] if not result_df.empty else 0
            logger.info(f"{query_name}: {count_val:,}")
        else:
            logger.info(f"{query_name}: {len(result_df):,} rows")
    
    logger.info(f"Comprehensive report saved to: {report_path}")
    

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    logger.info("Starting AI File Differ script...")
    main()