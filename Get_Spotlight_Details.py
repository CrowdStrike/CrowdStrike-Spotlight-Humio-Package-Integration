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

class Spotlight_Details():

    def get_vul_details(**kwargs):
        vulnerability_ids = kwargs.get('vulnerability_ids')
        base_url = kwargs.get('base_url')
        start_time = kwargs.get('starttime')
        token = kwargs.get('token')
        remedy_q = kwargs.get('remedy_q')
        processed_data_q = kwargs.get('processed_data_q')
        push_data = kwargs.get('push_data')
        proxy_used = kwargs.get('proxy_used')
        proxies = kwargs.get('proxies')
        log_level = kwargs.get('log_level')
        log_file = kwargs.get('log_file')
        version = kwargs.get('version')
        
        logging.basicConfig(filename=log_file, filemode='a+', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level) 

        retrieve_data=[]

        #pull a list of vulnerability IDs out of the list
        if len(vulnerability_ids) == 0:
            return
        else:
            details_list = vulnerability_ids.pop(-1)
        
        #need to track the list length for proper URL construction
        list_len = len(details_list)
        
        for l in details_list:
            while list_len > 1:
                get_id = details_list.pop(-1)
                query_id = 'ids=' + get_id + '&'
                retrieve_data.append(query_id)
                list_len = list_len-1

            #the last id doesn't have the '&' symbol 
            query_id= 'ids=' + l 
            retrieve_data.append(query_id)

            #create a properly formated Spotlight details request URL
            ids=str(retrieve_data)[1:-1]   
            ids=ids.replace("'", "").replace(",", "").replace(" ", "")

            details_url = base_url + config.CS_spotlight_details_endpoint+ '?'
            ret_details_url = details_url + ids   
            payload={}
            headers = {'Authorization': 'Bearer ' + token, 'accept': 'application/json' }
            logging.info('Spotlight2Humio v' + version + ': Preparing to collect vulnerability details')

            try:
                logging.info('Spotlight2Humio v' + version + ': details  query proxy enable = ' + str(proxy_used))
                if proxy_used == False:
                    details_response = requests.request("GET", ret_details_url, headers=headers, data=payload)
                elif proxy_used == True:
                    details_response = requests.request("GET", ret_details_url, headers=headers, data=payload, proxy=proxies)
                details_resp_code = str(details_response.status_code)
            
            except Exception as e:
                logging.error('Spotlight2Humio v' + version + ': Unable to collect vulnerability data from CrowdStrike ' + e.message + '  ' + e.args)
                sys.exit('Spotlight2Humio v' + version + ' : Unable to vulernability IDs to complete data collection, please correct any issues and try again.')

            logging.info('Spotlight2Humio v' + version + ': details  query response code: ' + details_resp_code)

            if details_resp_code.startswith('20'):
                pass
            else:
                sys.exit('Spotlight2Humio v' + version + ' : Unable to vulernability IDs to complete data collection, please correct any issues and try again - response code: ' + str(details_response.status_code))

            det_resp = details_response.json()
            results = det_resp['resources']
            logging.info('Spotlight2Humio v' + version + ': Vulnerability details were successfully retrieved.')


            logging.info('Spotlight2Humio v' + version + ': Number of results: ' + str(len(results)))

            
            for i in results:
                
                remed_id = i['remediation']['ids']
                if remed_id != None:
                    for r in remed_id:
                        if r not in remedy_q.queue:
                            remedy_q.put(r)
                        else:
                            pass
                push_data.append(i)
                logging.debug('Spotlight2Humio v' + version + ': Push length: ' + str(len(push_data)))
                processed_data_q.put(i)

            kwargs['processed_data_q'] = processed_data_q
            kwargs['remedy_q'] = remedy_q
            kwargs['push_data'] = push_data
            return(kwargs)

    def start_threads(**kwargs):
        log_level = kwargs.get('log_level')
        log_file = kwargs.get('log_file')
        version = kwargs.get('version')
        vulnerability_ids = kwargs.get('vulnerability_ids') 
        total_len = kwargs.get('total_len')
        starttime = kwargs.get('starttime')
        push_data=[]
        kwargs['push_data']=push_data

        logging.basicConfig(filename=log_file, filemode='a+', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level) 


        if (starttime + datetime.timedelta(minutes=25)) < datetime.datetime.now():
            logging.info('Spotlight2Humio v' + version + ': Token is within 5 minutes of expiration, retrieving a new token')
            logging.debug('Spotlight2Humio v' + version + ': The start time is: ' +str(starttime + datetime.timedelta(minutes=25)))
            token = auth.get_token(**kwargs)
            token_time = datetime.datetime.now()
            kwargs['token_time']=token_time
            kwargs['token']=token

        else:
            pass
        
        #Queues to hold vulnerability details and remediation IDs
        remedy_q= Queue()
        kwargs['remedy_q']=remedy_q
        #processed_data=[]
        processed_data_q = Queue()
        kwargs['processed_data_q']=processed_data_q

        #admin variables
        num_threads = 4
        batches_processed =0
        threads = []

        while len(vulnerability_ids) > 0:
            for id in range(0, num_threads):
                if len(vulnerability_ids)==0:
                    logging.info('Spotlight2Humio v' + version + ': No additional vulnerability ids to process')
                    break

                worker = Thread(target=Spotlight_Details.get_vul_details, kwargs=kwargs)
                worker.setDaemon(True)
                worker.start()
                threads.append(worker)
                batches_processed = batches_processed + 1

            for t in threads:
                t.join()

        #timestamp that shows the end of API calls & processing
        end_collect_time = (datetime.datetime.now())
        kwargs['end_collect_time']=end_collect_time 
        starttime = kwargs.get('starttime')
        processed_data_q = kwargs.get('processed_data_q') 
        remedy_q = kwargs.get('remedy_q')
        details = kwargs.get('details_results')

        logging.info('Spotlight2Humio v' + version + ' Details: Details Start Time: ' + str(starttime) + '   End Time: ' + str(end_collect_time))
        logging.info('Spotlight2Humio v' + version + 'Details: Total Length Reported: ' +str(kwargs.get('total_len')))
        logging.info('Spotlight2Humio v' + version + 'Details: Total of Vulnerabilty Queue: ' + str(processed_data_q.qsize()))
        logging.info('Spotlight2Humio v' + version + 'Details: Total of Remediation Queue: ' + str(remedy_q.qsize()))
        logging.info('Spotlight2Humio v' + version + 'Details: Batches processed: ' + str(batches_processed))

        return kwargs
