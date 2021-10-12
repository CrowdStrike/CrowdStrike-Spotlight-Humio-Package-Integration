#!/usr/bin/env python

import json
import datetime
import logging

#local imports
from CS_OAuth2_Base import OAuth2 as auth
import CrowdStrikeSpotlight2HumioConfig as config
from Get_Spotlight_Details import Spotlight_Details as details
from Get_Spotlight_IDs import Get_Spotlight_IDs as ids
from Send2HumioHEC import Send_to_HEC as humio
from Get_Spotlight_Remediations import Spotlight_Remedies as remedy

def main():
    #config pulls
    log_level = config.CS_spotlight_log_level
    log_file = config.log_file
    version = config.CS_spotlight_version

    #set up logging information
    logging.basicConfig(filename=log_file, filemode='a+', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level)
    logging.info('Spotlight2Humio v' + version + ': CrowdStrike Spotlight data to Humio is starting')

    limit = config.CS_spotlight_limit
    spot_filter = config.CS_spotlight_filter
    clientID = config.CS_spotlight_client_id
    secret = config.CS_spotlight_client_secret
    base_url=config.CS_spotlight_base_url
    tokenURL= base_url + config.CS_spotlight_tokenURL
    proxy_used = config.CS_spotlight_proxy
    proxies = config.CS_spotlight_proxies
    user_agent = 'Spotlight2Humio_V'+str(version)
    starttime=datetime.datetime.now()
    kwargs = {'base_url':base_url, 'limit':limit, 'spot_filter':spot_filter, 'clientID':clientID, 'secret':secret, 'tokenURL':tokenURL, 'user_agent':user_agent, 'proxies':proxies, 'starttime':starttime, 'log_level':log_level, 'log_file':log_file, 'version':version, 'proxy_used':proxy_used, 'proxies':proxies} 

    kwargs = ids.get_vuln_ids(**kwargs)
    num_vul_ids = len(kwargs['vulnerability_ids'])
    logging.info('Spotlight2Humio v' + version + ': Number of vulnerability IDs returned = '+ str(num_vul_ids))
    kwargs = details.start_threads(**kwargs)

    '''
            kwargs['processed_data_q'] = processed_data_q
            kwargs['remedy_q'] = remedy_q
            kwargs['push_data'] = push_data'''

    remedy_q = kwargs.get('remedy_q')
    #processed_data_q = kwargs.get('push_data')
    details_results = kwargs.get('push_data')
    logging.info('Spotlight2Humio v' + version + ': Processing vulnerabillty data to send to Humio')
    str_results= "\n".join(map(str,details_results))

    if 'null' or 'None' in str_results:
        str_results = str_results.replace("None", "[]")
        str_results = str_results.replace("null", "[]")
    str_results = str_results.replace("'", '"')
    str_results2 = json.dumps(str_results)
    str_results2 = json.loads(str_results2)
    data_type = 'vulnerabilities'

    humio.send_to_HEC(str_results2, data_type)

    kwargs = remedy.get_vul_details(**kwargs)
    rem_results_raw = kwargs.get('rem_results')
    rem_results = "\n".join(map(str,rem_results_raw))
    if 'null' or 'None' in rem_results:
        rem_results = rem_results.replace("None", "[]")
        rem_results = rem_results.replace("null", "[]")
    rem_results = rem_results.replace("'", '"')
    rem_results2 = json.dumps(rem_results)
    rem_results2 = json.loads(rem_results2)
    data_type = 'remediations'

    humio.send_to_HEC(rem_results2, data_type)

if __name__ == "__main__":
    main()