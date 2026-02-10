import os
import sys
import json
from datetime import datetime, timedelta
import boto3
import requests

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import libs.service_registry_sidecar_requests as service_registry_sidecar_requests

USERNAME = 'national-merit-attributes-service'
SVC_ENV = 'nonprod'
PASS_PARAM =  '/NMSQT/nonprod/ServiceRegistry/Password'

def get_sr_pwd():
    return boto3.Session(profile_name='rp').client('ssm', region_name='us-east-1').get_parameter(Name=PASS_PARAM, WithDecryption=True)["Parameter"]["Value"]
    
def get_msref_api_key_header(env_type):
    key = boto3.Session(profile_name='rp').client('ssm', region_name='us-east-1').get_parameter(Name=f'/NMSQT/{env_type}/msReference/APIKey', WithDecryption=True)["Parameter"]["Value"]
    return {"X-API-KEY": f"{key}"}

def get_sr_client(svc_env, sr_uname, sr_pwd):
    return service_registry_sidecar_requests.ServiceRegistryClient(svc_env, sr_uname, sr_pwd)

def make_simple_msreference_call(sr_client, service='msreference', asmt_event_env_name='oak', domain=None, method='GET', url=None):
    url = url or f"/reference/{domain}"
    response = sr_client.request(service, asmt_event_env_name, method, url)
    return response.json()



## TEST MSASMTEVENT
# __sr_password = get_sr_pwd()

# client = service_registry_sidecar_requests.ServiceRegistryClient(SVC_ENV, USERNAME, __sr_password)

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

#****************************************************
## TEST MSREFERENCE

ms_ref_base_url = "https://msreference.cds-nonprod.collegeboard.org/oak"

# ms_reference_api_key = boto3.Session(profile_name='rp').client('ssm', region_name='us-east-1').get_parameter(Name="/NMSQT/nonprod/msReference/APIKey", WithDecryption=True)["Parameter"]["Value"]

# headers = {"X-API-KEY": f"{ms_reference_api_key}"}

ms_ref_url_template = f"{ms_ref_base_url}/getDomainV1?cbDomain=state&cbActiveInd=false"

# response = requests.get(url=ms_ref_url_template, headers=headers)
# print(response.json())

#*****************************************************
# GET ASMTEVENTS

education_period_cds_call = {
        "service": "msasmtevents",
        "method": "GET",
        "url_template": "/asmtEvents/educationPeriodCd/{education_period_cd}",
    }

def get_ed_period_cds(row):
    current_year = (datetime.utcnow() - timedelta(days=365-92)).year
    for education_periodD in row["cdRefList"]:
        if "code" in education_periodD and education_periodD["code"] in ("0", "99999"):
            continue
         
        start_dt = list(filter(lambda attrD: attrD["name"] == "education_period_start_dt", education_periodD["attributes"]))[0]["value"]
        start_dt = datetime.strptime(start_dt, "%Y-%m-%dT%H:%M:%S.%fZ")
        if start_dt.year > current_year + 1:
            continue
        
        yield {"education_period_cd": education_periodD["code"], "domain": "asmt-event", "service": "msAsmtEvents"}

edu_period_stmt = {"domain": "education-period", "service": "msReference"}
ed_period_url_tempate = f"{ms_ref_base_url}/getDomainV1?cbDomain=education-period&cbActiveInd=false"

response = requests.get(url=ed_period_url_tempate, headers=get_msref_api_key_header('nonprod'))
ed_period_cds = get_ed_period_cds(response.json()) # Generator

_sr_pwd = get_sr_pwd()
sr_client = get_sr_client(SVC_ENV, USERNAME, _sr_pwd)
asmt_event_responses = []

def collect_asmt_event_data(ed_period_cds, education_period_cds_call, sr_client, year_lower=None, year_upper=None):
    asmt_event_responses = []
    
    for ed_period_cdD in ed_period_cds:
        print(f"Calling msAsmtEvents for EdPeriodCd {ed_period_cdD}")
        education_period_cd = ed_period_cdD["education_period_cd"]
        url = education_period_cds_call["url_template"].format(education_period_cd=education_period_cd)
        ed_period_response = make_simple_msreference_call(
            sr_client=sr_client,
            service=education_period_cds_call["service"],
            asmt_event_env_name='oak',
            method='GET', 
            url=url
        )
        if year_lower and year_upper:
            # print(ed_period_response)
            for asmt_event in ed_period_response['asmtEvents']:
                if asmt_event.get("adminYear") and year_lower <= asmt_event.get("adminYear") <= year_upper:
                    asmt_event_responses.append(asmt_event)
            # asmt_event_responses.extend(filter(lambda asmt_event: year_lower <= asmt_event["adminYear"] <= year_upper, ed_period_response['asmtEvents']))
        else:
            asmt_event_responses.extend(ed_period_response['asmtEvents'])
    return asmt_event_responses

# for ed_period_cdD in ed_period_cds:
#     print(f"Calling msAsmtEvents for EdPeriodCd {ed_period_cdD}")
#     education_period_cd = ed_period_cdD["education_period_cd"]
#     url = education_period_cds_call["url_template"].format(education_period_cd=education_period_cd)
#     ed_period_response = make_simple_msreference_call(
#         sr_client=sr_client,
#         service=education_period_cds_call["service"],
#         asmt_event_env_name='oak',
#         method='GET', 
#         url=url
#     )
    
#     asmt_event_responses.extend(ed_period_response['asmtEvents'])

asmt_event_responses = collect_asmt_event_data(ed_period_cds, education_period_cds_call, sr_client, year_lower=2024, year_upper=2025)

with open('asmt_events_data_081225.json', 'w') as f:
    json.dump(asmt_event_responses, f)