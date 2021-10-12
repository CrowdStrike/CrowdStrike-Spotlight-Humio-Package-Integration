#get vulnerability details

#python imports
import requests
import logging
import sys
import datetime
from queue import Queue
from threading import Thread
from os import path

from CS_OAuth2_Base import OAuth2 as auth
import CrowdStrikeSpotlight2HumioConfig as config

class Spotlight_Remedies():

    def get_vul_details(**kwargs):
        base_url = kwargs.get('base_url')
        token = kwargs.get('token')
        remedy_q = kwargs.get('remedy_q')
        push_data = kwargs.get('push_data')
        proxy_used = kwargs.get('proxy_used')
        proxies = kwargs.get('proxies')
        log_level = kwargs.get('log_level')
        log_file = kwargs.get('log_file')
        version = kwargs.get('version')

        logging.basicConfig(filename=log_file, filemode='a+', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level) 

        remedy_ids =[]
        retrieve_data = []

        while remedy_q.empty() == False:
            remedy_ids.append(remedy_q.get())
        
        list_len = len(remedy_ids)
        
        for l in remedy_ids:
            while list_len > 1:
                get_id = remedy_ids.pop(-1)
                query_id = 'ids=' + get_id + '&'
                retrieve_data.append(query_id)
                list_len = list_len-1

            #the last id doesn't have the '&' symbol 
            query_id= 'ids=' + l 
            retrieve_data.append(query_id)

            #create a properly formated Spotlight details request URL
            ids=str(retrieve_data)[1:-1]   
            ids=ids.replace("'", "").replace(",", "").replace(" ", "")

            details_url = base_url + config.CS_spotlight_remediation_endpoint+ '?'
            rem_details_url = details_url + ids   
            payload={}
            headers = {'Authorization': 'Bearer ' + token, 'accept': 'application/json' }
            logging.info('Spotlight2Humio v' + version + ': Preparing to collect remediation details')

            try:
                logging.info('Spotlight2Humio v' + version + ': remediation query proxy enable = ' + str(proxy_used))
                if proxy_used == False:
                    details_response = requests.request("GET", rem_details_url, headers=headers, data=payload)
                elif proxy_used == True:
                    details_response = requests.request("GET", rem_details_url, headers=headers, data=payload, proxy=proxies)
                details_resp_code = str(details_response.status_code)
            
            except Exception as e:
                logging.error('Spotlight2Humio v' + version + ': Unable to collect vulnerability data from CrowdStrike ' + e.message + '  ' + e.args)
                sys.exit('Spotlight2Humio v' + version + ' : Unable perform remediation data collection, please correct any issues and try again.')

            logging.info('Spotlight2Humio v' + version + ': remediations  query response code: ' + details_resp_code)

            if details_resp_code.startswith('20'):
                pass
            else:
                sys.exit('Spotlight2Humio v' + version + ' : Unable ro collect Remediation details, please correct any issues and try again - response code: ' + str(details_response.status_code))

            det_resp = details_response.json()
            rem_results = det_resp['resources']
            kwargs['rem_results'] = rem_results
            print(rem_results)
            logging.info('Spotlight2Humio v' + version + ': Remediation details were successfully retrieved.')
            return(kwargs)