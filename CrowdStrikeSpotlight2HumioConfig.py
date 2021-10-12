

import logging


#Set Logging Level and file name
CS_spotlight_log_level = logging.DEBUG
log_file = 'CrowdStrikeSpotlight2Humio.log'

#Code version - do not alter
CS_spotlight_version = '1.0'

#Proxy config
CS_spotlight_proxy = False
CS_spotlight_proxies = {}
#Example of Proxy syntex {"http": "http://myproxy:8888", "https": "https://myotherproxy:8080"}

#####CrowdStrike Spotlight Configuration

#CrowdStrike API Filters
CS_spotlight_limit = 'limit=390' #Do not increase limit
CS_spotlight_filter = "&filter=created_timestamp:>'2021-10-11T00:00:12Z'" #Time may be configured but needs to remain in single quotation marks

#CrowdStrike API credential with Spotlight Scope
CS_spotlight_client_id=""
CS_spotlight_client_secret=""


#Indicates the CrowdStrike cloud to connect to, this URL can be found in the Falcon UI
CS_spotlight_base_url = 'https://api.crowdstrike.com'

#CrowdStrike API endpoints 
CS_spotlight_tokenURL = "/oauth2/token"
CS_spotlight_vuln_endpoint = '/spotlight/queries/vulnerabilities/v1'
CS_spotlight_details_endpoint = '/spotlight/entities/vulnerabilities/v2'
CS_spotlight_remediation_endpoint = '/spotlight/entities/remediations/v2'

#####Humio HEC configuration

#Humio URL
Humio_base_URL = ''
HumioHECurl = Humio_base_URL + '/api/v1/ingest/hec/raw'
#sample full HEC URL = http://192.168.1.229:8080/api/v1/ingest/hec/raw

#Humio HEC Token
HumioHECtoken_Spotlight_Vulerabilies = ''
HumioHECtoken_Spotlight_Remediations = ''

#Header Content Type
HumioHECContent_Spotlight  = "{'Content-Type': 'application/json', 'Accept':'application/json'}"

#Certficate validation - should only be set to false in a controlled test environment 
HumioHECverify = True




