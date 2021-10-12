#!/usr/bin/env python
#CrowdStrike OAuth2 Token Retrieval

import requests
import logging
import sys


class OAuth2():

    # get the OAuth2 bearer token
    def get_token(**kwargs):
        clientID = kwargs.get('clientID')
        secret = kwargs.get('secret')
        tokenURL = kwargs.get('tokenURL')
        user_agent = kwargs.get('user_agent')
        proxies = kwargs.get('proxies')
        proxy_used = kwargs.get('proxy_used')
        log_level = kwargs.get('log_level')
        log_file = kwargs.get('log_file')
        version = kwargs.get('version')
        proxy_used = kwargs.get('proxy_used')
        proxies = kwargs.get('proxies')
        
        logging.basicConfig(filename=log_file, filemode='a+', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level) 

        session = requests.Session()
        headers = {'content-type': 'application/x-www-form-urlencoded', 'user-agent': user_agent}

        payload = 'client_id=%s&client_secret=%s' %(clientID, secret)
        if proxy_used == True:
            logging.info('Spotlight2Humio v' + version + ': No proxiy configured')
            pass
        elif proxy_used == False:
            logging.info('Spotlight2Humio v' + version + ': Proxy is configured')
            session.proxies.update(proxies)
        
        logging.info('Spotlight2Humio v' + version + ': Auth: Proxy configured: ' + str(proxy_used))

        logging.info('Spotlight2Humio v' + version + ': Auth: Preparing to acwuire OAuth2 token')
        try:
            token = session.post(tokenURL, data=payload, headers=headers)
            result_code = str(token.status_code)
            logging.info('Spotlight2Humio v' + version + ':  OAuth2 bearer token API call result: ' + result_code)
            
            if result_code.startswith('20'):
                logging.info('Spotlight2Humio v' + version + ': Successful authentication and retrieval of OAuth2 bearer token.')
                token = token.json()
                bearer_token = token['access_token']
                return bearer_token
            else:
                response = token.reason
                logging.error('Spotlight2Humio v' + version + ': Unable to successfully authenticate and retrieve OAuth2 bearer token. Data collection is not possible without a valid token. Please address the access issue and restart the input. Error Code: ' + result_code + ' Error Description: ' + str(response))
                sys.exit('Spotlight2Humio v' + version + ' Spotlight2Humio is shutting down.')
        
        except Exception as e:
            logging.error('Spotlight2Humio v' + version + ': Fatal error attempting to acquire a OAuth2 token from CrowdStrike ' + e.message + '  ' + e.args)
            try:
                sys.exit('Spotlight2Humio v' + version + ': Spotlight2Humio is shutting down.')
            except:
                pass