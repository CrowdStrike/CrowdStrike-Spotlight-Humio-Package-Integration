import sys

def connection_errors(logging, log_label, headers, body, status_code):
    
    if 'X-Cs-Traceid' in headers:
        logging.error(log_label + 'When contacting CrowdStrike support please provide thie trace_id: ' + str(headers['X-Cs-Traceid']))
    elif 'trace_id' in body:
        logging.error(log_label + 'When contacting CrowdStrike support please provide thie trace_id: ' + str(body['trace_id']))
    else:
        logging.error(log_label + 'There was an issue contacting the API. The return code value was ' + status_code)
        logging.error(log_label + 'The response body was ' + str(body))
    logging.error(log_label + 'Please correct any issues and retry')
    sys.exit()