import os
import sys
import json
import argparse
import boto3
import requests

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import libs.service_registry_sidecar_requests as service_registry_sidecar_requests

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

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('env_type', action='store', choices=['prod', 'nonprod'], help='env type (prod/nonprod)')
    parser.add_argument('tree_env_name', action='store', choices=['maple', 'spruce', 'palm', 'prod', 'oak', 'pine'])
    
    args = parser.parse_args()
    
    SVC_ENV = args.env_type
    USERNAME = 'national-merit-attributes-service'
    PASS_PARAM =  f'/NMSQT/{SVC_ENV}/ServiceRegistry/Password'
    
    if SVC_ENV == 'prod':
        profile_name = 'rp-prod'
        # ms_ref_base_url = "https://msreference.cds-prod.collegeboard.org/prod"
        parameter_str = "/NMSQT/prod/msReference/APIKey"
        # tree_env = 'prod'
    else:
        profile_name = 'rp'
       
        parameter_str = "/NMSQT/nonprod/msReference/APIKey"
    tree_env = args.tree_env_name
    
    ms_ref_base_url = f"https://msreference.cds-{SVC_ENV}.collegeboard.org/{tree_env}"
    ethnicity_type = "ethnicity-epd"
    # ms_ref_base_url = f"https://msreference.cds-nonprod.collegeboard.org/{tree_env}"
    print(ms_ref_base_url)

    ## TEST MSASMTEVENT
    __sr_password = boto3.Session(profile_name=profile_name).client('ssm', region_name='us-east-1').get_parameter(Name=PASS_PARAM, WithDecryption=True)["Parameter"]["Value"]

    client = service_registry_sidecar_requests.ServiceRegistryClient(SVC_ENV, USERNAME, __sr_password)

    # response = client.request('msreference', 'nonprod', 'GET', '/reference/countries')
    
    

    # print(type(response))
    # print(dir(response))
    # print(response.connection)
    # print()
    # print(response.headers)
    # print()
    # print(response.status_code)
    # print()
    # print(response.request)
    # print()
    # print(response.url)
    # print()
    # print(response.text)

    ## TEST MSREFERENCE

    ms_reference_api_key = boto3.Session(profile_name=profile_name).client('ssm', region_name='us-east-1').get_parameter(Name=parameter_str, WithDecryption=True)["Parameter"]["Value"]

    headers = {"X-API-KEY": f"{ms_reference_api_key}"}

    CB_DOMAIN = "ethnicity"
    # CB_DOMAIN = "education-level"
    CB_ACTIVE_IND = "false"
    url_template = f"{ms_ref_base_url}/getDomainV1?cbDomain={CB_DOMAIN}&cbActiveInd={CB_ACTIVE_IND}"

    # country_code = "CA"
    
    # url_template = f"{ms_ref_base_url}/getDomainV2?cbDomain=CountryRegions&miscParam1={country_code}"
    
    response = requests.get(url=url_template, headers=headers)
    # response = requests.post(url=url_template, headers=headers)
    print(response.headers)
    print(response.url)
    # print(response.text)
    # from pprint import pp
    # pp(response.json())
    # with open("ed_level.json", 'w') as f:
    with open("race_psat.json", 'w') as f:
        json.dump(response.json(), f)