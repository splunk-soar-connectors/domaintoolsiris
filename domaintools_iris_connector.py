# --
# File: domaintools_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App

import json
from datetime import datetime, timedelta
import hmac
import hashlib

import requests

# Define the App Class
class DomainToolsConnector(BaseConnector):
    ACTION_ID_DOMAIN_REPUTATION = "domain_reputation"
    ACTION_ID_DOMAIN_ENRICH = "domain_enrich"
    ACTION_ID_WHOIS_DOMAIN = "whois_domain"
    ACTION_ID_PIVOT  = "pivot_action"
    ACTION_ID_REVERSE_IP = "reverse_lookup_ip"
    ACTION_ID_REVERSE_EMAIL = "reverse_whois_email"
    ACTION_ID_REVERSE_DOMAIN = "reverse_lookup_domain"
    ACTION_ID_LOAD_HASH= "load_hash"



    DOMAINTOOLS = 'api.domaintools.com'
    API_VERSION = 'v1'

    def __init__(self):

        # Call the BaseConnectors init first
        super(DomainToolsConnector, self).__init__()

        self._ssl = None
        self._username = None
        self._key = None

    def initialize(self):
        # get the app version
        self.app_version_number = self.get_app_json().get('app_version', '')
        return phantom.APP_SUCCESS

    def _clean_empty_response(self, response):
        # PAPP-2087 DomainTools - Reverse Email table widget shows contextual action for no domain
        if response.get('domains') == []:
            del response['domains']

    def _parse_response(self, action_result, r, response_json, ignore400=False):
        """
        No need to do exception handling, since this function call has a try...except around it.
        If you do want to catch a specific exception to generate proper error strings, go ahead
        """

        status = r.status_code
        response = response_json.get('response')
        error = response_json.get('error', {})

        if (status == 404) or (
                        (status == 400) and (ignore400) and (error.get('message', '').startswith('No IP addresses'))):
            action_result.add_data({})
            return action_result.set_status(phantom.APP_SUCCESS,
                                            error.get('message', 'Domain Tools failed to find IP/Domain'))

        if (status == 200) and (response):
            self._clean_empty_response(response)
            action_result.add_data(response)
            return action_result.set_status(phantom.APP_SUCCESS)

        return action_result.set_status(phantom.APP_ERROR,
                                        error.get('message', 'An unknown error occurred while querying domaintools.'))

    def _do_query(self, endpoint, action_result, data=None, ignore400=False):
        if data is None:
            data = dict()

        ssl = 's'

        if not self._ssl:
            ssl = ''

        full_endpoint = '/{}/{}/'.format(self.API_VERSION, endpoint)
        url = 'http{}://{}{}'.format(ssl, self.DOMAINTOOLS, full_endpoint)

        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

        sig_message = self._username + timestamp + full_endpoint

        sig = hmac.new(str(self._key), str(sig_message), digestmod=hashlib.sha1)

        data['api_username'] = self._username
        data['timestamp'] = timestamp
        data['signature'] = sig.hexdigest()
        data['app_name'] = 'phantom_domaintools_iris'
        data['app_version'] = self.app_version_number
        data['app_partner'] = 'phantomcyber'

        self.save_progress("Connecting to domaintools")

        try:
            self.save_progress("url is : {} (data {})".format(url, data))
            r = requests.post(url, data=data)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "REST API failed", e)

        self.save_progress("Parsing response...")
        try:
            response_json = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as a valid JSON", e)

        self.debug_print(r.url)


        # Now parse and add the response into the action result
        try:
            return self._parse_response(action_result, r, response_json, ignore400=ignore400)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, 'An error occurred while parsing domaintools reponse', e)

        return phantom.APP_SUCCESS

    def _test_connectivity(self):
        params = {'domain': "domaintools.net"}

        self.save_progress("Performing test query")

        # Progress
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, 'domaintools.com')

        action_result = self.add_action_result(ActionResult(dict(params)))

        try:
            self._do_domain_enrich(action_result, params)
            if action_result.get_status() != phantom.APP_SUCCESS:
                raise Exception(action_result.get_message())
        except Exception as e:
            message = 'Failed to connect to domaintools.com'
            self.set_status(phantom.APP_ERROR, message, e)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, 'Successfully connected to domaintools.com.\nTest Connectivity passed')


    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        # Get the config
        config = self.get_config()

        self._ssl = config['ssl']
        self._username = config['username']
        self._key = config['key']

        if action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity()
        elif action_id == self.ACTION_ID_DOMAIN_ENRICH:
            ret_val = self._domain_enrich(param)
        elif action_id == self.ACTION_ID_DOMAIN_REPUTATION:
            ret_val = self._domain_reputation(param)
        elif action_id == self.ACTION_ID_PIVOT:
            ret_val = self._pivot_action(param)
        elif action_id == self.ACTION_ID_REVERSE_IP:
            updates = {'pivot_type':'ip', 'query_value':param['ip'], 'ip':param['ip']}
            param.update(updates)
            ret_val = self._pivot_action(param)
        elif action_id == self.ACTION_ID_REVERSE_EMAIL:
            updates = {'pivot_type':'email', 'query_value':param['email'], 'email':param['email']}
            param.update(updates)
            ret_val = self._pivot_action(param)
        elif action_id == self.ACTION_ID_REVERSE_DOMAIN:
            ret_val = self._reverse_domain(param)
        elif action_id == self.ACTION_ID_LOAD_HASH:
            data = {'pivot_type':'search_hash', 'query_value':param['hash'], 'hash':param['hash']}
            param.update(data)
            ret_val = self._pivot_action(param)

        return ret_val
    def _reverse_domain(self, param):
        action_result = self.add_action_result(ActionResult(param))
        params = {'domain': param.get('domain')}
        ret_val = self._do_query('iris-investigate', action_result, data=params)

        if not ret_val:
            return action_result.get_data()

        data = action_result.get_data()

        if not data:
            return action_result.get_status()

        ips = []

        for a in data[0]['results'][0]['ip']:
            if 'address' in a:
                ips.append( { 'ip':a['address']['value'], 'type':'Host IP', 'count': a['address']['count']  } )

        for a in data[0]['results'][0]['mx']:
            if 'ip' in a:
                for b in a['ip']:
                    ips.append( { 'ip':b['value'], 'type':'MX IP', 'count': b['count']  } )

        for a in data[0]['results'][0]['name_server']:
            if 'ip' in a:
                for b in a['ip']:
                    ips.append( { 'ip':b['value'], 'type':'NS IP', 'count': b['count']  } )

        action_result.update_summary({'ip_list': ips })

        return action_result.get_status()

    def _domain_enrich(self, param):
        action_result = self.add_action_result(ActionResult(param))
        params = {'domain': param.get('domain')}
        return self._do_domain_enrich(action_result, params)

    def _do_domain_enrich(self, action_result, params):
        ret_val = self._do_query('iris-investigate', action_result, data=params)
        return action_result.get_status()

    def _domain_reputation(self, param):

        action_result = self.add_action_result(ActionResult(param))
        domain_to_query = param['domain']
        params = {'domain': domain_to_query}

        ret_val = self._do_query('iris-investigate',  action_result, data=params)

        if not ret_val:
            return action_result.get_data()

        data = action_result.get_data()

        if not data:
            return action_result.get_status()

        action_result.update_summary({'domain_risk': data[0]['results'][0]['domain_risk']['risk_score']})

        for a in data[0]['results'][0]['domain_risk']['components']:
            if(a['name'] == "whitelist"):
              action_result.update_summary({'is_whitelisted': True})
            else:
              action_result.update_summary({a['name']: a['risk_score']})

        return action_result.get_status()

    def _pivot_action(self, param):
        action_result = self.add_action_result(ActionResult(param))

        query_field = param['pivot_type']
        query_value = param['query_value']

        params = {query_field: query_value}

        if 'tld' in param:
            params['tld'] = param['tld']

        if 'data_updated_after' in param:
            params['data_updated_after'] = param['data_updated_after']
            if params['data_updated_after'].lower() == 'today':
                params['data_updated_after'] = datetime.today().strftime('%Y-%m-%d')
            if params['data_updated_after'].lower() == 'yesterday':
                params['data_updated_after'] = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')

        if 'create_date' in param:
            params['create_date'] = param['create_date']
            if params['create_date'].lower() == 'today':
                params['create_date'] = datetime.today().strftime('%Y-%m-%d')
            if params['create_date'].lower() == 'yesterday':
                params['create_date'] = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')

        if 'expiration_date' in param:
            params['expiration_date'] = param['expiration_date']
            if params['expiration_date'].lower() == 'today':
                params['expiration_date'] = datetime.today().strftime('%Y-%m-%d')
            if params['expiration_date'].lower() == 'yesterday':
                params['expiration_date'] = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')

        if 'status' in param and param['status'].lower() != 'any':
            params['active'] = 'true' if param['status'].lower() == 'active' else 'false'

        ret_val = self._do_query('iris-investigate', action_result, data=params)

        if not ret_val:
            return action_result.get_data()

        data = action_result.get_data()
        if 'results' in data[0]:
            action_result.update_summary({'Connected Domains Count':len(data[0]['results'])})

        if data[0]['limit_exceeded']:
            msg = data[0]['message']
            action_result.update_summary({'Error':msg})
            return action_result.set_status(phantom.APP_ERROR, msg)


        return action_result.get_status()

if __name__ == '__main__':

    import sys
    import pudb

    #pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = DomainToolsConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
