##!/usr/bin/env python

# This client is powered by CrowdStrike's FalconPy SDK
# For more information on the SDK visit: https://github.com/CrowdStrike/falconpy

# local imports
import os
from falconpy import SpotlightVulnerabilities
from CrowdStrikeSpotlight2HumioErrorsV2 import connection_errors
from Send2HumioHECV2 import send_to_HEC

# python imports
import logging
import sys
import configparser
import json
from datetime import datetime


def main():

    # config pulls
    config = configparser.ConfigParser()
    config_file = os.environ.get(
        "CONFIG_FILE", "CrowdStrikeSpotlight2HumioConfig.ini")
    config.read(config_file)
    checkpoint_file = os.environ.get(
        "CHECKPOINT_FILE", "CrowdStrikeSpotlight2HumioConfig.ini")
    checkpoint = configparser.ConfigParser()
    checkpoint.read(config_file)
    log_config = config['Logging']
    cs_config = config['CrowdStrike']

    # client version
    __version__ = "1.0.0-next.1"
    version = __version__ = "1.0.0-next.1"

    # logging settings and construct log file timestamp
    starttime = datetime.utcnow()
    log_time = starttime.strftime("%b-%d-%Y_%H-%M-%S")
    log_level = log_config['log_level']
    if "LOG_FILE" in os.environ:
        log_file_raw = os.environ.get("LOG_FILE")
    else:
        log_file_raw = log_config['log_file']
    log_file = log_file_raw + '_v' + version + '_' + str(log_time) + '.log'

    # set up logging information
    # For container use if specified as - use STD out rather than file

    if log_file_raw == "-":
        logging.basicConfig(
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level)
    else:
        logging.basicConfig(filename=log_file, filemode='a+',
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level)
    log_label = 'Spotlight2Humio v' + version + ': '
    logging.info(log_label + 'CrowdStrike Spotlight data to Humio is starting')

    # getting CS based configs
    limit = int(cs_config['limit'])
    spot_base_filter = cs_config['filter']
    spot_time = cs_config['time_filter']
    facets = cs_config['facets']

    if "FALCON_BASE_URL" in os.environ:
        base_url = os.environ.get("FALCON_BASE_URL")
    else:
        base_url = cs_config['base_url']
    if "FALCON_CLIENT_SECRET" in os.environ:
        secret = os.environ.get("FALCON_CLIENT_SECRET")
    else:
        secret = cs_config['client_secret']
    if "FALCON_CLIENT_ID" in os.environ:
        clientID = os.environ.get("FALCON_CLIENT_ID")
    else:
        clientID = cs_config['client_id']
    proxy_used = cs_config['proxy_used']
    # convert proxy settings to dictionary
    if proxy_used == 'True':
        proxies = json.loads(cs_config['proxies'])
    else:
        proxies = {}
    user_agent = f"crowdstrike-spotlight2humio/{version}"
    read_timeout = int(cs_config['timeout_read'])
    conn_timeout = int(cs_config['timeout_conn'])

    # configure timeout settings
    timeout = (read_timeout, conn_timeout)
    checkpoint_current = checkpoint['CrowdStrike']
    updated_timestamp = checkpoint_current['updated_timestamp']
    sort = cs_config['sort']

    # ensure that any timestamps are enclosed in single quotes
    if updated_timestamp:
        if not updated_timestamp.startswith("'"):
            updated_timestamp = "'" + updated_timestamp + "'"
        spot_filter = spot_base_filter + updated_timestamp

    else:
        if not spot_time.startswith("'"):
            spot_time = "'" + spot_time + "'"
        spot_filter = spot_base_filter + spot_time

    # check to ensure that clientID and secrets ahve been properly entered
    if len(clientID) != 32 or len(secret) != 40:
        logging.error(log_label + 'Please ensure that the API credentials have been properly recorded in the configuration file prior to running this collection. The client is now shutting down.')
        sys.exit()

    # Initial attempt to collect vulnerability data
    try:
        falcon = SpotlightVulnerabilities(client_id=clientID, client_secret=secret,
                                          base_url=base_url, proxy=proxies, user_agent=user_agent, timeout=timeout)
        if facets:
            logging.info(
                log_label + 'there is Facet data configured to be collected')
            response = falcon.query_vulnerabilities_combined(
                base_url=base_url, limit=limit, filter=spot_filter, proxy=proxies, facet=facets, sort=sort)
        else:
            logging.info(
                log_label + 'Facet data is not configured be collected')
            response = falcon.query_vulnerabilities_combined(
                base_url=base_url, limit=limit, filter=spot_filter, proxy=proxies, sort=sort)

        ir_status_code = str(response['status_code'])
        headers = response['headers']
        body = response['body']

    except Exception as e:
        logging.error(
            log_label + 'Unable to contact the CrowdStrike API. The error returned was: ' + str(e))
        logging.error(log_label + 'The Client will now exit')
        sys.exit()

    if ir_status_code.startswith('2'):
        logging.info(
            log_label + 'The initial API call appears to have been successful.')
        data = body['resources']

    else:
        connection_errors(logging, log_label, headers, body, ir_status_code)

    total_vul_ids = body['meta']['pagination']['total']

    # determine if there are any vulnerabilities to actually process
    if total_vul_ids == 0:
        logging.info(
            log_label + 'There is currently no data matching the criteria to collect, client will now exit.')
        sys.exit()
    else:
        logging.info(
            log_label + ' The total number of vulnerabilities identified = ' + str(total_vul_ids))

        logging.info(
            log_label + 'Preparing to send initial data collection to Humio')
        send_to_HEC(logging, log_label, data, config, updated_timestamp)

    # identify if the pagination offset value actually needs to be leveraged or not
    if total_vul_ids > int(limit):
        pagination_needed = True
        after_value = body['meta']['pagination']['after']
        logging.info(
            log_label + 'Pagination has been identified as being needed')
    else:
        pagination_needed = False
        logging.info(
            log_label + 'Paginiation has not been identified as being needed')

    # while necessary make additional paginiation calls and extend vulnerability list
    total_vul_collected = 0
    while pagination_needed == True:
        try:
            if facets:
                logging.info(
                    log_label + 'Facet data is configured to be collected')
                after_response = falcon.query_vulnerabilities_combined(
                    base_url=base_url, limit=limit, filter=spot_filter, proxy=proxies, facet=facets, after=after_value, sort=sort)
            else:
                logging.info(
                    log_label + 'Facet data is not configured to be collected')
                after_response = falcon.query_vulnerabilities_combined(
                    base_url=base_url, limit=limit, filter=spot_filter, proxy=proxies, after=after_value, sort=sort)

        except Exception as e:
            logging.error(
                log_label + 'Unable to contact the CrowdStrike API for pagination. The error returned was: ' + str(e))
            logging.error(log_label + 'The client is now exiting')
            sys.exit()

        after_status_code = str(after_response['status_code'])
        after_headers = after_response['headers']
        after_body = after_response['body']

        if after_status_code.startswith('2'):
            logging.info(
                log_label + 'A pagination API call appears to have been successful.')

        else:
            logging.error(
                log_label + 'A pagination API call appears to have failed.')
            connection_errors(logging, log_label, after_headers,
                              after_body, after_status_code)

        after_data = after_body['resources']

        data.extend(after_data)
        logging.info(
            log_label + 'Current length of data dict:' + str(len(data)))
        logging.info(log_label + 'Total to collect is ' + str(total_vul_ids))

        logging.info(log_label + 'Preparing to send pagination data to Humio')
        send_to_HEC(logging, log_label, after_data, config, updated_timestamp)

        total_vul_collected = len(data)
        if total_vul_ids > total_vul_collected:
            pagination_needed = True
            after_value = after_body['meta']['pagination']['after']
        else:
            pagination_needed = False

    logging.info(log_label + 'Vulnerability processing has completed. Total number of vulnerabilities identified: ' +
                 str(total_vul_ids) + ' Total number of vulnerabilities processed: ' + str(total_vul_collected))
    sys.exit()


if __name__ == "__main__":
    main()
