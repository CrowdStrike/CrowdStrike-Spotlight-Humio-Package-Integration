import requests
import logging
import sys

#local imports
import CrowdStrikeSpotlight2HumioConfig as config

class Send_to_HEC():

    def send_to_HEC(event_data, event_type):

        HumioHECurl = config.HumioHECurl
        if event_type == 'vulnerabilities':
            HumioHECtoken =config.HumioHECtoken_Spotlight_Vulerabilies
        elif event_type == 'remediations':
            HumioHECtoken =config.HumioHECtoken_Spotlight_Remediations
        HumioHECcontent = config.HumioHECContent_Spotlight
        HumioHECverify = config.HumioHECverify
        log_level = config.CS_spotlight_log_level
        version = config.CS_spotlight_version
        proxy_used = config.CS_spotlight_proxy
        proxies = config.CS_spotlight_proxies

        logging.basicConfig(filename=config.log_file, filemode='w', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level)
        
        logging.info('Spotlight2Humio v' + version + ': HEC: Sending data to Humio HEC')

        try:
            header = {"Authorization": "Bearer " + HumioHECtoken, "Content-Type": HumioHECcontent} 
            if proxy_used == False:
                r = requests.post(url=HumioHECurl, headers=header, data= event_data.encode('utf-8'), verify=HumioHECverify, timeout=300)
            elif proxy_used == False:
                r = requests.post(url=HumioHECurl, headers=header, data= event_data.encode('utf-8'), verify=HumioHECverify, timeout=300, proxy=proxies)
            transmit_result = r.status_code
            logging.info('Spotlight2Humio v' + version + ': HEC: Transmission status code for data push to HEC= '+ str(transmit_result))
            logging.info('Spotlight2Humio v' + version + ': HEC: Transmission of CrowdStrike Spotlight data successful')

        except requests.exceptions.RequestException as e:
            error=str(e)
            logging.info('Spotlight2Humio v' + version + ': HEC: Unable to evaluate and transmit sensor_data event: Error: ' + error)
            try:
                sys.exit('Spotlight2Humio v' + version + ': HEC: This is fatal error, please review and correct the issue - Spotlight2Humio is shutting down')
            
            except:
                pass
