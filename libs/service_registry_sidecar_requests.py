"""
This module is used to hide the details of connecting to the CB Service Registry.  It uses the `requests` library.  

By: Tim Ludwinski

Functionality Usage
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    client = ServiceRegistryClient(service_env_type, username, password)
    response = client.get("msnationalmerit", "dev", "/reference/national-merit-message/")
    print(response.json()) # Returns the result from the `requests` library
    
Command Line Usage
~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    python -m service_registry_sidecar_requests <service_name> <service_env> <url_path> [--method <method>] [--env_type <env_type>] [--username <username>] [--json <json>] [--body <body>] [--options <options>] [--aws-param-for-pwd <aws_param_for_pwd>] [--aws-profile <aws_profile>]
"""
import time
import logging
from contextlib import contextmanager

import requests
import requests.auth
from jwt import JWT

__all__ = [
    "SR_CONFIG",
    "ServiceRegistryError",
    "ServiceRegistryAuthenticationError",
    "ServiceRegistryResponseError",
    "ServiceRegistryServiceNotFoundError",
    
    "ServiceRegistryAuth",
    "ServiceRegistryClient",
]

@contextmanager
def translate_exception(new_exception, exception_cls=Exception): # pragma: no cover
    try:
        yield
    except exception_cls as e:
        raise new_exception from e

SR_CONFIG = {
    "prod": {
        "baseUrl": "https://serviceregistry-prod-api.collegeboard.org/prod",
        "namespace": "cbapis.prod",
    },
    "nonprod": {
        "baseUrl": "https://serviceregistry-preprod-api.collegeboard.org/preprod",
        "namespace": "cbapis.preprod",
    },
}

class ServiceRegistryError(Exception):
    """ The base class for SR Errors """

class ServiceRegistryAuthenticationError(ServiceRegistryError):
    """ The Authentication to the SR failed """

class ServiceRegistryResponseError(ServiceRegistryError):
    """ The SR returned an invalid response """

class ServiceRegistryServiceNotFoundError(ServiceRegistryError):
    """ The service requested from the service registry could not be found in the service registry datastore """

_jwt = JWT()
class ServiceRegistryAuth(requests.auth.AuthBase): # pragma: no cover
    """ A class for dealing with service registry auth (not sure why you would want to use this on its own) """
    def __init__(self, service_env_type, username, password, additonal_auth_params={}):
        self.service_env_type = service_env_type
        # self.jwt = JWT()
        self.logger = logging.getLogger("ServiceRegistryClient")
        # Not using a session because: 1. Calls will not be made very often, so no need to leave connections open.  2.  We should be able to pass this auth between threads/processes.  
        # self._auth_session = requests.Session() # TODO: allow passing parameters here. - (small enhancement, allow passing Session into the class and if it doesn't exist, create one)
        self._initialize_sr_creds(username, password)
    
    def _initialize_sr_creds(self, username, password):
        self.logger.info(f"Getting SR creds for {self.service_env_type} SR")
        auth_request = {"serviceName": username, "servicePassword": password}
        with translate_exception(ServiceRegistryResponseError("SR Auth call returned and error")):
            r = requests.post(f'{SR_CONFIG[self.service_env_type]["baseUrl"]}/authenticate', json=auth_request)
        if r.status_code in (401, 403):
            raise ServiceRegistryAuthenticationError("Authentication with the service registry failed")
        with translate_exception(ServiceRegistryResponseError("SR Auth call returned and error")):
            r.raise_for_status()
        with translate_exception(ServiceRegistryResponseError("SR Response isn't valid JSON")):
            auth_data = r.json()
        self.logger.info(f"Received SR creds for {self.service_env_type} SR")
        
        if 'IdToken' not in auth_data or 'RefreshToken' not in auth_data:
            raise ServiceRegistryResponseError("Data returned from Service Registry Auth doesn't have required fields")
        
        self.id_token, self.refresh_token = auth_data['IdToken'], auth_data['RefreshToken']
        
        with translate_exception(ServiceRegistryResponseError("JWT Token Failed to parse")):
            jwt_payload = _jwt.decode(self.id_token, do_verify=False, algorithms=['RS256']) # Note: no need to verify the token, since this is only passed along to the called service
        self.token_expiration = jwt_payload['exp']
    
    def _renew_api_token(self):
        self.logger.info(f"Refreshing SR creds for {self.service_env_type} SR")
        with translate_exception(ServiceRegistryResponseError("SR Auth Renew call returned and error")):
            r = requests.post(f'{SR_CONFIG[self.service_env_type]["baseUrl"]}/refreshtoken', json={"refreshToken": self.refresh_token})
        if r.status_code in (401, 403):
            raise ServiceRegistryAuthenticationError("Renewing Authentication with the service registry failed")
        with translate_exception(ServiceRegistryResponseError("SR Auth Renew call returned and error")):
            r.raise_for_status()
        with translate_exception(ServiceRegistryResponseError("SR Response isn't valid JSON")):
            auth_data = r.json()
        self.logger.info(f"Refreshed SR creds for {self.service_env_type} SR")
        
        if 'IdToken' not in auth_data:
            raise ServiceRegistryResponseError("Data returned from Service Registry Auth doesn't have required fields")
        # self.id_token, self.refresh_token = auth_data['IdToken'], auth_data['RefreshToken'] # TODO: shouldn't we be getting a new refresh token?? (artifact from translation from old version, reference Service Registry Sidecar for clarification)
        self.id_token = auth_data['IdToken']
        
        with translate_exception(ServiceRegistryResponseError("JWT Token Failed to parse")):
            jwt_payload = _jwt.decode(self.id_token, do_verify=False, algorithms=['RS256']) # Note: no need to verify the token, since this is only passed along to the called service
        self.token_expiration = jwt_payload['exp']
    
    def _get_api_token(self):
        if self.token_expiration - time.time() < 60 * 5: # 5 minutes
            self._renew_api_token()
        return self.id_token
    
    def __call__(self, req):
        """ Add SR Creds Header """
        req.headers = req.headers or []
        if isinstance(req.headers, dict):
            req.headers = list(req.headers.items())
        
        # req.headers.append(('Authorization', self._get_api_token()))
        req.headers['Authorization'] = self._get_api_token()
        
        return req

class ServiceRegistryClient: # pragma: no cover
    """ This class is a wrapper around `requests.Session` that automatically get the service details, 
        adds the Service Registry authentication, and builds the proper URL for the service.  
        
        Usage Example:
        >>> client = ServiceRegistryClient(service_env_type, username, password)
        >>> response = client.get("msnationalmerit", "dev", "/reference/national-merit-message/")
        >>> print(response.json()) # Returns the result from the `requests` library
    """
    def __init__(self, service_env_type, username=None, password=None, auth=None):
        """
        Note: only one environment is allowed per `ServiceRegistryClient`.  
        You can't connect to "prod" and "nonprod" with the same `ServiceRegistryClient`.  
        If you need to do that, create a second `ServiceRegistryClient`.  
        """
        self.service_env_type = service_env_type
        self._session = requests.Session() # TODO: allow passing parameters here. (small enhancement, allow passing Session into the class and if it doesn't exist, create one)  
        if auth:
            self._session.auth = auth
        else:
            self._session.auth = ServiceRegistryAuth(service_env_type, username, password)
        
        self._function_cache = {}
        self._service_info_cache = {}
        
        self.sr_base_url = SR_CONFIG[service_env_type]["baseUrl"]
        self.sr_namespace = SR_CONFIG[service_env_type]["namespace"]
        
        self.logger = logging.getLogger("ServiceRegistryClient")
    
    def _get_service_info(self, service_name, service_env):
        """ Retrives the service information from the Service Registry """
        if (service_name, service_env) in self._service_info_cache:
            return self._service_info_cache[(service_name, service_env)]
        
        params = {
            "env": service_env
        }
        
        self.logger.info(f"Requesting service info for {service_name} found in {service_env}")
        with translate_exception(ServiceRegistryResponseError("SR call returned and error")):
            r = requests.get(f'{self.sr_base_url}/namespaces/{self.sr_namespace}/services/{service_name}/instances', params=params)
            r.raise_for_status()
        with translate_exception(ServiceRegistryResponseError("SR Response isn't valid JSON")):
            instance_info = r.json()
        instanceL = [i for i in instance_info['Instances'] if i['Attributes']['env'] == service_env]
        
        self.logger.info(f"{len(instanceL)} instance of {service_name} found in {service_env}")
        if len(instanceL) < 1:
            raise ServiceRegistryServiceNotFoundError(f'Service registry couldn\'t find "{service_env}" environment of service "{service_name}".  SR type: "{self.service_env_type}"')
        
        self._service_info_cache[(service_name, service_env)] = instanceL[0]['Attributes']
        
        return self._service_info_cache[(service_name, service_env)]
    
    def _get_session_function_proxy(self, name):
        """ Returns a function that wraps a `requests` HTTP API call (such as `requests.get`) and adds the SR service info """
        if name in self._function_cache:
            return self._function_cache[name]
        else:
            # Create and cache the function proxy
            def _call_with_sr_creds(*args, **kwargs):
                # Extract args
                if name != "request":
                    service_name, service_env, url = args[0:3]
                    method = name
                    new_args = args[3:]
                else:
                    service_name, service_env, method, url = args[0:4]
                    new_args = args[4:]
                
                # Get service info
                service_info = self._get_service_info(service_name, service_env)
                
                # Add api-id header
                kwargs['headers'] = kwargs.get('headers') or {}
                # if isinstance(kwargs['headers'], dict):
                #     kwargs['headers'] = list(kwargs['headers'].items())
                # kwargs['headers'].append(('x-apigw-api-id', service_info["apiId"]))
                kwargs['headers']['x-apigw-api-id'] = service_info["apiId"]
                
                r = self._session.request(method, f'{service_info["url"]}/{service_info["stage"]}{url}', *new_args, **kwargs)
                
                self._post_metrics(r)
                
                return r
            
            self._function_cache[name] = _call_with_sr_creds
            return _call_with_sr_creds
    
    def _post_metrics(self, r):
        """ TODO: implement this (in a thread so it doesn't block the main thread down) """
        pass
    
    def __getattr__(self, name: str):
        """ This method wraps requests HTTP calls to add the needed SR parameters """
        if name in ("request", "get", "head", "post", "patch", "put", "delete", "options"):
            return self._get_session_function_proxy(name)
        else:
            return getattr(self._session, name)

def make_and_print_request(service_name, service_env, sr_env_type, method, url, username, sr_password, additional_options={}): # pragma: no cover
    """ Make a single request, printing the response (for testing) """
    print(f'Connecting to "{sr_env_type}" service registry with username "{username}"')
    sr_client = ServiceRegistryClient(sr_env_type, username=username, password=sr_password)
    
    print(f'{method} request to service {service_name} at {url} in {service_env} environment') # TODO: print query parameters from `additional_options`.  Maybe use a prepared request to help with printing... (safe to ignore for now)
    if additional_options.get("headers"):
        print("Request Headers: ")
        # TODO: hide potentially sensitive headers (can implement a filtering list of known potentially sensitive headers)
        for header_name, header_value in additional_options.get("headers").items():
            print(" - %s: %s" % (header_name, header_value))
    print(additional_options)
    resp = sr_client.request(service_name, service_env, method, url, **additional_options)
    
    print("HTTP Status: HTTP/%s.%s %d %s" % (str(resp.raw.version)[0], str(resp.raw.version)[1:], resp.status_code, resp.reason))
    print("Response Headers: ")
    for header_name, header_value in resp.headers.items():
        print(" - %s: %s" % (header_name, header_value))
    print()
    
    print(resp.text)

if __name__ == "__main__": # pragma: no cover
    import sys
    import argparse
    import json
    
    import boto3
    
    parser = argparse.ArgumentParser(description='Call a Service Registry Service')
    
    parser.add_argument("service_name", help='The name of the service to call.')
    parser.add_argument("service_env", help='The environment of the service (defined by the service.  It may be anything).')
    parser.add_argument("url_path", help='The path in the request, including any query parameters (example "/student/nm-attributes/123?fields=gpoReasonCd".')
    
    parser.add_argument("--method", default="GET", help='The HTTP verb to use (ie GET, POST, PUT, HEAD, etc.)')
    parser.add_argument("--env_type", default=None, choices=["nonprod", "prod"], help='The service registry environment type.  If not specified, we will attempt to guess.')
    parser.add_argument("--username", default=None, help='The username to authenticate to the service.')
    parser.add_argument("--json", default=None, help='A string to be passed to the service as json')
    parser.add_argument("--body", default=None, help='A string to be passed directly to the service as the request body')
    parser.add_argument("--options", default="{}", help='Additional options passed to the service as json dictionary.')
    
    parser.add_argument("--aws-param-for-pwd", default=None, help='A string to be passed directly to the service as the request body')
    parser.add_argument("--aws-profile", default=None, help='The AWS profile used for retrieving the password')
    
    args = parser.parse_args()
    
    logging.basicConfig(stream=sys.stdout, format='%(asctime)s - %(name)s - %(message)s', level=logging.INFO)
    
    if not args.username:
        print("Please Specify a username")
        exit(1)
    
    if not args.env_type:
        if args.service_env in ("prod", "preprod", "pine"):
            sr_env_type = 'prod'
        else:
            sr_env_type = 'nonprod'
    else:
        sr_env_type = args.env_type
    
    if args.aws_param_for_pwd:
        password_param = args.aws_param_for_pwd # '/NMSQT/nonprod/ServiceRegistry/Password'
        __sr_password = boto3.Session(profile_name=args.aws_profile).client('ssm', region_name='us-east-1').get_parameter(Name=password_param, WithDecryption=True)["Parameter"]["Value"]
    else:
        import getpass
        __sr_password = getpass.getpass(f"Enter the Service Registry Password for User [args.username]: ")
    
    if args.json and args.body:
        logging.error("Either specify --body or --json, but not both")
        exit(1)
    
    try:
        options = json.loads(args.options)
    except (ValueError, TypeError):
        logging.error("Options must be a json object: %s" % (args.options))
        exit(1)
    
    if args.json is not None:
        if "json" in options:
            logging.warning("json specified multiple times")
        try:
            options["json"] = json.loads(args.json)
        except (ValueError, TypeError):
            logging.error("Passed in json string isn't valid json")
            exit(1)
    
    if args.body is not None:
        if "data" in options:
            logging.warning("body specified multiple times")
        options["data"] = args.body
    
    make_and_print_request(args.service_name, args.service_env, sr_env_type, args.method, args.url_path, args.username, __sr_password, options)
