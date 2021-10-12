#!/usr/bin/env python

#python imports
import requests
import sys
import datetime
import sys
import logging

#local imports
from CS_OAuth2_Base import OAuth2 as auth
import CrowdStrikeSpotlight2HumioConfig as config

class Get_Spotlight_IDs():

    def get_vuln_ids (**kwargs):
        token = auth.get_token(**kwargs)
        log_level = kwargs.get('log_level')
        log_file = kwargs.get('log_file')
        version = kwargs.get('version')
        base_url = kwargs.get('base_url')
        limit = kwargs.get('limit')
        starttime = kwargs.get('starttime')
        spot_filter = kwargs.get('spot_filter')
        proxy_used = kwargs.get('proxy_used')
        proxies = kwargs.get('proxies')

        endpoint = config.CS_spotlight_vuln_endpoint

        logging.basicConfig(filename=log_file, filemode='a+', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level) 
        
        #list to store retrieved IDs 
        vuln_ids = []

        #create query pieces
        url = base_url + endpoint + '?' + limit + spot_filter
        payload={}
        headers = {'Authorization': 'Bearer ' + token, 'accept': 'application/json' }

        #initial data pull for vulnerability IDs
        logging.info('Spotlight2Humio v' + version + ': Attempting to pull Spotlight vulernability IDs')
        try:
            if proxy_used == False:
                response = requests.request("GET", url, headers=headers, data=payload)
            elif proxy_used == True:
                response = requests.request("GET", url, headers=headers, data=payload, proxy= proxies)
            vuln_list = response.json()
            num_vul = len(vuln_list['resources'])
            logging.debug('Spotlight2Humio v' + version + ': Number of resources returned = ' + str(num_vul))

        except Exception as e:
            logging.error('Spotlight2Humio v' + version + ': Unable to collect vulnerability IDs from CrowdStrike ' + e.message + '  ' + e.args)
            sys.exit('Spotlight2Humio v' + version + ' : Unable to vulernability IDs to complete data collection, please correct any issues and try again')
        if num_vul == 0:
            sys.exit('Spotlight2Humio v' + version + ': No IDs were returned, nothing to process - Spotlight2Humio is now exiting')
        total_len = vuln_list['meta']['pagination']['total']
        base_resp = vuln_list['resources']
        after_val = len(vuln_list['meta']['pagination']['after'])
        logging.info('Spotlight2Humio v' + version + ': IDs: Total ID count is: ' + str(total_len))

        #check to see if the data exceeds the limit - prep for paginiation
        if after_val > 0:
            logging.debug('Spotlight2Humio v' + version + ': IDs: The response indicates that pagination is required to collect all of the available IDs.')
            pagination = True
            after_key = vuln_list['meta']['pagination']['after']

        else:
            pagination = False

        #add list to parent list for processing later
        vuln_ids.append(base_resp)
        logging.debug('Spotlight2Humio v' + version + ': IDs: Number if IDs in base processed: ' + str(len(base_resp)))

        #handle requests with pagination
        while pagination == True:
            after = '?after=' + str(after_key)
            pag_url = (base_url + endpoint + after + '&' + limit + spot_filter)

            if (starttime + datetime.timedelta(minutes=25)) < datetime.datetime.now():
                logging.info('Spotlight2Humio v' + version + ': Token is within 5 minutes of expiration, retrieving a new token')
                logging.debug('Spotlight2Humio v' + version + ': IDs: The start time is: ' +str(starttime+ datetime.timedelta(minutes=25)))
                token = auth.get_token(**kwargs)
                token_time = datetime.datetime.now()
                kwargs['token_time']=token_time
                kwargs['token']=token
            else:
                pass

            try:
                if proxy_used == False:
                    pag_response = requests.request("GET", pag_url, headers=headers, data=payload)
                elif proxy_used == True:
                    pag_response = requests.request("GET", pag_url, headers=headers, data=payload, proxy=proxies)
                pag_resp = pag_response.json()
                if 'errors' in pag_resp:
                    pag_errors = pag_resp['errors']
                    logging.error('Spotlight2Humio v' + version + ': ' + str(pag_errors[0]))
                    break
                else:
                    logging.info('Spotlight2Humio v' + version + ': Collection is paginating')

                #create a list of the pagination responses and add them
                pag_list = pag_resp['resources']
                vuln_ids.append(pag_list)
                logging.info('Spotlight2Humio v' + version + ': Processed ' + str(len(pag_list)) + ' number of IDs')

                #check to see if additional pagination is required
                if len(pag_resp['meta']['pagination']['after']) > 0:
                    pagination = True
                    after_key = pag_resp['meta']['pagination']['after']
                else:
                    pagination = False
                    logging.debug('Spotlight2Humio v' + version + ': IDS: Done Paginating')

            except Exception as e:
                logging.error('Spotlight2Humio v' + version + ': There was an issue with paginating through the Spotlight ID response ' + e.message + '  ' + e.args)
                sys.exit('Spotlight2Humio v' + version + ' : Critical error while retrieving Spotlight IDS, Spotlight2Humio will not exit')
            
        end_time=datetime.datetime.now()
        total_proc = []
        for l in vuln_ids:
            for i in l:
                total_proc.append(i)
        fin_list = len(total_proc)
        fin_set = len(set(total_proc))
        if fin_list == fin_set and fin_list == total_len:
            logging.debug('Spotlight2Humio v' + version + ': Data consistency check passed')
        else:
            logging.debug('Spotlight2Humio v' + version + ': Data is not consistent.')

        logging.info('Spotlight2Humio v' + version + ': ID processing completed')
        logging.info('Spotlight2Humio v' + version + ': Total data count: ' + str(total_len))
        logging.info('Spotlight2Humio v' + version + ': Total number of IDs: ' + str(len(vuln_ids)))
        logging.debug('Spotlight2Humio v' + version + ': Starttime: ' + str(starttime) + '   Endtime: ' + str(end_time))
        kwargs['token'] = token
        kwargs['vulnerability_ids'] = vuln_ids
        kwargs['total_len'] = total_len 
        kwargs['starttime'] = starttime 
        kwargs['total_proc']=total_proc

        return (kwargs)
