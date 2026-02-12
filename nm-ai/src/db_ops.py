from functools import lru_cache
import logging
import os
import sys

import boto3
import pandas as pd
import psycopg2

logger = logging.getLogger(__name__)

PARAM_TRANSLATION_TEMPLATE = {
    '/NMSQT/{env_name}/{db_name}/Host': 'host',
    '/NMSQT/{env_name}/{db_name}/Database': 'database',
    '/NMSQT/{env_name}/{db_name}/Port': 'port',
    '/NMSQT/{env_name}/{db_name}/Username': 'user',
    '/NMSQT/{env_name}/{db_name}/Password': 'password',
}


class DatabaseConnection:
    """Wrapper class for a psycopg2 connection."""

    def __init__(self, connection_params):
        self.connection_params = connection_params
        self.psycopg2_conn = None
        self._initialized = False

    def _initialize_connection(self):
        if self._initialized:
            return
        self.psycopg2_conn = psycopg2.connect(**self.connection_params, sslmode="require")
        self._initialized = True

    def get_raw_connection(self):
        """Get raw connection for direct SQL execution (DDL, etc.)."""
        self._initialize_connection()
        return self.psycopg2_conn

    def get_engine_type(self):
        """Return the current engine type being used."""
        return 'psycopg2'


def get_database_parameters(db_name, env_name):
    """Retrieve database parameters from AWS Systems Manager Parameter Store."""
    param_translation = {k.format(db_name=db_name, env_name=env_name): v for k, v in PARAM_TRANSLATION_TEMPLATE.items()}

    try:
        response = boto3.client('ssm').get_parameters(
            Names=list(param_translation.keys()),
            WithDecryption=True,
        )
    except Exception as exc:
        logger.error("Error fetching parameters: %s", exc)
        sys.exit(1)

    paramsD = {}
    if response['Parameters']:
        logger.info("Found %s parameters for %s in %s", len(response['Parameters']), db_name, env_name)
    else:
        logger.error("No parameters found for %s in %s", db_name, env_name)
        sys.exit(1)

    for param_info in response['Parameters']:
        if param_info['Name'] in param_translation:
            paramsD[param_translation[param_info['Name']]] = param_info['Value']

    return paramsD


@lru_cache
def get_cornerstone_connection(env_name):
    """Establish a connection to the Cornerstone database."""
    logger.info("Fetching DB Params")
    paramsD = get_database_parameters("Cornerstone", env_name)

    logger.info("Connecting to Cornerstone Server at %s", paramsD['host'])
    db_conn = DatabaseConnection(paramsD)
    logger.info("Connected using %s engine", db_conn.get_engine_type())

    return db_conn


def run_query(db_conn, sql):
    """Execute a SQL query and return a pandas DataFrame."""
    if isinstance(db_conn, DatabaseConnection):
        raw_conn = db_conn.get_raw_connection()
        if raw_conn is not None:
            return pd.read_sql(sql, raw_conn)  # type: ignore[arg-type]
        raise RuntimeError("Failed to get psycopg2 connection")

    return pd.read_sql(sql, db_conn)  # type: ignore[arg-type]


def execute_sql(db_conn, sql):
    """Execute a SQL statement that doesn't return results (DDL, INSERT, etc.)."""
    if isinstance(db_conn, DatabaseConnection):
        raw_conn = db_conn.get_raw_connection()
        if raw_conn is not None:
            cursor = raw_conn.cursor()
            try:
                cursor.execute(sql)
                raw_conn.commit()
            finally:
                cursor.close()
    else:
        cursor = db_conn.cursor()
        try:
            cursor.execute(sql)
            db_conn.commit()
        finally:
            cursor.close()
    return None


def prep_queries_from_sql_files(query_file_path, parameter_overrideD=None):
    """Prepare queries from SQL files."""
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
                except KeyError as exc:
                    logger.error("Missing parameter %s in file %s", exc, sql_file)
                    logger.error(
                        "Available parameters: %s",
                        list(parameter_overrideD.keys()) if parameter_overrideD else 'None',
                    )
                    raise

            output.append((sql_filename, full_sql))
    except Exception as exc:
        logger.error("Error preparing queries: %s", exc)
        raise
    return output


def iterate_queries(conn, args, query_dir, return_result=True, query_filterL=None, parameter_overrideD=None):
    """Iterate through and execute queries from SQL files in a directory."""
    prepped_queries = prep_queries_from_sql_files(query_dir, parameter_overrideD)
    results = {}

    for k, v in prepped_queries:
        if query_filterL and k not in query_filterL:
            continue
        if args.verbose:
            logger.info("Running query for %s", k)
        if return_result:
            results[k] = run_query(conn, v)
        else:
            execute_sql(conn, v)

    return results
