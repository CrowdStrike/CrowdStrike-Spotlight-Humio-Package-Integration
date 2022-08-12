Configuration File Explainations

This client is powered by CrowdStrike's FalconPy SDK
For more information on the SDK visit: https://github.com/CrowdStrike/falconpy

For information about the Spotlight API visit: https://falcon.crowdstrike.com/documentation/98/spotlight-apis 


[Logging]
log_level = INFO                                                #set to debug for troubleshooting                                            
log_file = LogFiles/CrowdStrikeSpotlight2Humio

[CrowdStrike]
client_version = 2.0                                            #do not alter
proxy_used = False                                              #set to True for proxy usage
proxies = {}                                                    #configure with proper python proxy syntax
limit = 490
filter = updated_timestamp:>                                    #at least 1 filter must be set, updated_timestamp is the best timestamp to use
time_filter = '2021-10-11T00:00:12Z'                            #timestamp to start from, must be enclosed in single quotes
                                                                #keep in mind the retention policy for Humio when setting this as older data will not be retained
updated_timestamp = '2022-06-16T21:33:56Z'                      #timestamp populated by client for follow on queries, no not populate/modify
sort = updated_timestamp|asc                                    #sorting logic, recommended this not be modified
client_id =                                                     #CrowdStrike ClientID for API access
client_secret =                                                 #CrowdStrike Secret for API access
base_url = https://api.crowdstrike.com                          #Base URL for CrowdStrike Falcon Instance, adjust for proper cloud 
facets = cve, remediation, host_info, evaluation_logic          #additional data collection with optional facets
timeout_conn = 30                                               #connection timeout
timeout_read = 300                                              #read timeout

[Humio]
hecurl = https://cloud.us.humio.com/api/v1/ingest/hec/raw       #standard Humio Cloud HEC URL, adjust as needed
humiohectoken =                                                 #Humio HEC token
content-type = application/json                                 #HEC post header setting, do not modify
accept = application/json                                       #HEC post header setting, do not modify
humiohecverify = True                                           #HEC SSL verify setting, modified only if needed