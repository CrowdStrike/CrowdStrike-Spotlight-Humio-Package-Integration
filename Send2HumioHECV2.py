#!/usr/bin/env python

# python imports
import json
import requests
import sys
import os
from humiolib.HumioClient import HumioIngestClient
from dateutil import parser

# local imports
from CrowdStrikeSpotlight2HumioErrorsV2 import connection_errors

checkpoint_file = os.environ.get(
    "CHECKPOINT_FILE", "CrowdStrikeSpotlight2HumioConfig.ini")


def send_to_HEC(logging, log_label, event_data, config, updated_timestamp):

    # collects configuration parameters
    humio_config = config['Humio']
    if "HUMIO_HEC_URL" in os.environ:
        HumioHECurl = os.environ.get("HUMIO_HEC_URL")
    else:
        HumioHECurl = humio_config['HECurl']
    if "HUMIO_HEC_TOKEN" in os.environ:
        HumioHECtoken = os.environ.get("HUMIO_HEC_TOKEN")
    else:
        HumioHECtoken = humio_config['HumioHECtoken']
    HumioContType = humio_config['Content-Type']
    HumioAppType = humio_config['Accept']
    if "HUMIO_HEC_VERIFY" in os.environ:
        HumioVerify = os.environ.get("HUMIO_HEC_VERIFY")
    else:
        HumioVerify = humio_config['HumioHECverify']
    # TLS Verify is the default if not correctly disabled it should be enabled
    if HumioVerify == 'False':
        HumioVerify = False
    else:
        HumioVerify = True

    # creates a line delimited JSON formatted event strucutre for the Humio HEC
    json_join = '\n'.join(json.dumps(vuln) for vuln in event_data)

    try:
        # configure requests call to Humio HEC
        header = {"Authorization": "Bearer " + HumioHECtoken,
                  "Content-Type": HumioContType, "Accept": HumioAppType}

        # perform data push to Humio's HEC
        HEC_response = requests.post(url=HumioHECurl, headers=header, data=(
            json_join), verify=HumioVerify, timeout=300)
        transmit_result = str(HEC_response.status_code)
        logging.info(
            log_label + ' HEC: Transmission status code for data push to HEC= ' + transmit_result)

        # evaluate HEC push results
        if transmit_result.startswith('20'):
            pass
        else:
            logging.error(
                log_label + ' HEC: Transmission error, please correct the issue and try again.')
            logging.error(log_label + ' HEC: Return code: ' +
                          str(transmit_result))
            logging.error(log_label + str(HEC_response))
            sys.exit('Correct Error to properly send data to the Humio HEC API')

        counter = len(event_data)

    except requests.exceptions.RequestException as e:
        error = str(e)
        logging.error(
            log_label + ' HEC: Unable to evaluate and transmit vulnerability events to Humio HEC: Error: ' + error)
        sys.exit(
            log_label + ' HEC: This is fatal error, please review and correct the issue - The client is shutting down')

    logging.info(log_label + ' HEC: Sent ' + str(counter) +
                 ' Vulnerability events to the Humio HEC')

    # examine the events to ensure that that latested updated_timestamp is collect
    for event in event_data:
        event_updated = event['updated_timestamp']
        if updated_timestamp:
            updated_test = parser.parse(str(updated_timestamp))
            checkpoint_test = parser.parse(event_updated)
            if checkpoint_test > updated_test:
                checkpoint = event_updated
                logging.debug(log_label + 'New Checkpoint detected')
            else:
                checkpoint = updated_timestamp
        else:
            checkpoint = event_updated

    # record the updated_timestamp to the configuration file for use in future calls
    try:
        config.set('CrowdStrike', 'updated_timestamp', "'"+str(checkpoint)+"'")
        with open(checkpoint_file, 'w') as configfile:
            config.write(configfile)

    except:
        logging.error(
            log_label + 'unable to update the updated_timestamp to the configuration file')

    logging.info(
        log_label + 'Successfully updated the updated_timestamp value in the configuration file')
    return
