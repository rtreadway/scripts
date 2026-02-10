import os
import sys
import json
import argparse
import boto3
import requests
from datetime import datetime, timedelta

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import libs.service_registry_sidecar_requests as service_registry_sidecar_requests

SERVICE_NAME = "msmetrics"
"""The name of the Service Registry service."""

NM_USERNAME = "national-merit-attributes-service"
"""The Service Registry username."""

SERVICE_REGISTRY_CALLS = {
    "education_period_cds": {
        "service": "msasmtevents",
        "method": "GET",
        "url_template": "/asmtEvents/educationPeriodCd/{education_period_cd}",
    },
    "asmt_event_option_dates": {
         "service": "msasmtevents",
        "method": "GET",
        "url_template": "/asmtEventOptionDates/asmtEventId/{asmt_event_id}",
    } 
}

def transform_asmt_events(row):
    """
    Transforms the assessment events in the given response data.

    This function iterates over the assessment events in the given response data and yields the transformed assessment events
    that meet certain criteria. The criteria for transformation are as follows:
    
    - The 'asmtFamilyCd' must be equal to 3.
    - The 'asmtId' must be equal to 100 or 119, and the 'asmtSubtypeCd' must be equal to 4.
    - Alternatively, the 'asmtId' can be equal to 76.

    Args:
        row (dict): The row containing assessment events.

    Yields:
        dict: The transformed assessment event.
    """
    for eventD in row["asmtEvents"]:
        if eventD["asmtFamilyCd"] == 3 and ((eventD["asmtId"] == 100 and eventD["asmtSubtypeCd"] == 4) or (eventD["asmtId"] == 119 and eventD["asmtSubtypeCd"] == 4) or eventD["asmtId"] == 76):
            yield eventD

def get_current_psat_year():
    """
    Get the current PSAT year.

    PSAT admin year starts 92 days from Dec. 31st (Oct. 1st).

    Returns:
        int: The current PSAT year.
    """
    return (datetime.utcnow() - timedelta(days=365-92)).year


def get_education_period_cds(row):
    """
    Retrieves education period codes from the given response data.

    This function iterates over the "cdRefList" in the response data and filters out education periods with specific codes.
    It checks the start date of each education period and only yields the ones that meet the following criteria:
    
    - The education period code is not "0" or "99999".
    - The start date is not more than one year ahead of the current year.

    Args:
        row (dict): A dictionary containing the response data.

    Yields:
        dict: A dictionary containing the education period code, service domain, and service name.
    """
    current_year = get_current_psat_year()
    print("CURRENT EDPERIOD ROW: ", row)
    for education_periodD in row["cdRefList"]:
        if "code" in education_periodD and education_periodD["code"] in ("0", "99999"):
            continue
         
        start_dt = list(filter(lambda attrD: attrD["name"] == "education_period_start_dt", education_periodD["attributes"]))[0]["value"]
        start_dt = datetime.strptime(start_dt, "%Y-%m-%dT%H:%M:%S.%fZ")
        if start_dt.year > current_year + 1:
            continue
        
        yield {"education_period_cd": education_periodD["code"], "domain": "asmt-event", "service": "msAsmtEvents"}

def get_asmt_events(row):
    """
    Retrieves assessment events from a given row.

    Args:
        row (list): A list containing assessment event data dicts.

    Yields:
        dict: A dictionary containing the assessment event ID, service domain, and service name.

    """
    for asmt_eventD in row:
        yield {"asmt_event_id": asmt_eventD["asmtEventId"], "domain": "asmt-event-option-dates", "service": "msAsmtEvents"}

def fetch_ed_level_cds(env_type, env_name):
    ms_reference_base_url = f"https://msreference.cds-{env_type}.collegeboard.org/oak" if env_name not in ("prod", "preprod") else "https://msreference.cds-prod.collegeboard.org/pine"
    ms_reference_api_key = boto3.client('ssm').get_parameter(Name=f"/NMSQT/{env_type}/msReference/APIKey", WithDecryption=True)["Parameter"]["Value"]
    education_period_cds = []

    MS_REFERENCE_API_TO_CALL = [
        {"domain": "education-period", "service": "msReference"},
    ]

    for api_data in MS_REFERENCE_API_TO_CALL:
        print(f'Fetching data for {api_data["domain"]}')
        url_template = f'{ms_reference_base_url}/getDomainV1?cbDomain={api_data["domain"]}&cbActiveInd=false'
        response = requests.get(url=url_template, headers={"X-API-KEY": ms_reference_api_key})
        # print("RESPONSE: ", response)
        db_record = response.json()
        education_period_cds = list(get_education_period_cds(db_record))
    for ed_level_cd in education_period_cds:
        yield ed_level_cd

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('env_type', action='store', choices=['prod', 'nonprod'], help='env type (prod/nonprod)')
    parser.add_argument('tree_env_name', action='store')
    
    args = parser.parse_args()
    
    env_type = args.env_type
    USERNAME = 'national-merit-attributes-service'
    PASS_PARAM =  f'/NMSQT/{env_type}/ServiceRegistry/Password'
    
    # if SVC_ENV == 'prod':
    #     profile_name = 'rp-prod'
    #     # ms_ref_base_url = "https://msreference.cds-prod.collegeboard.org/prod"
    #     parameter_str = "/NMSQT/prod/msReference/APIKey"
    #     # tree_env = 'prod'
    # else:
    #     profile_name = 'rp'
       
    #     parameter_str = "/NMSQT/nonprod/msReference/APIKey"
    
    tree_env = args.tree_env_name
    asmt_event_env_name = tree_env
    print("Preparing SR Client")
    sr_password = boto3.client('ssm').get_parameter(Name=f'/NMSQT/{env_type}/ServiceRegistry/Password', WithDecryption=True)["Parameter"]["Value"]
    sr_client = service_registry_sidecar_requests.ServiceRegistryClient(env_type, username=NM_USERNAME, password=sr_password)
    service_data = SERVICE_REGISTRY_CALLS["education_period_cds"]
    
    # Getting data from msAsmtEvents 
    asmt_events_responses = []
    for education_period_cd in fetch_ed_level_cds(env_type, tree_env):
        print(f"Calling msAsmtEvents for EdPeriodCd {education_period_cd}")
        url = service_data["url_template"].format(education_period_cd=education_period_cd["education_period_cd"])
        education_period_response = sr_client.request(service_data["service"], asmt_event_env_name, service_data["method"], url).json()
        asmt_events_responses.append(education_period_response)
    
    asmt_events_data = []
    for asmt_event_response in asmt_events_responses:
        asmt_events_data.extend(list(transform_asmt_events(asmt_event_response)))
    
    # asmt_events_api_record = api_call_to_db_record(asmt_events_data, "asmt-event", "msAsmtEvents")
    
    with open(f"asmt_event_{args.env_type}-{args.tree_env_name}.json", 'w') as f:
        json.dump(asmt_events_data, f)