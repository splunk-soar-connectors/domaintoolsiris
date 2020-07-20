# --
# File: domaintools_iris_connector.py
#
# Copyright (c) 2019-2020 DomainTools, LLC
#
# --

# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App

import sys
import json
from datetime import datetime, timedelta
import hmac
import hashlib

import requests
from bs4 import UnicodeDammit


# Define the App Class
class DomainToolsConnector(BaseConnector):
    ACTION_ID_DOMAIN_REPUTATION = "domain_reputation"
    ACTION_ID_DOMAIN_ENRICH = "domain_enrich"
    ACTION_ID_WHOIS_DOMAIN = "whois_domain"
    ACTION_ID_PIVOT = "pivot_action"
    ACTION_ID_REVERSE_IP = "reverse_lookup_ip"
    ACTION_ID_REVERSE_EMAIL = "reverse_whois_email"
    ACTION_ID_REVERSE_DOMAIN = "reverse_lookup_domain"
    ACTION_ID_LOAD_HASH = "load_hash"

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

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR,
                                   "Error occurred while getting the Phantom server's Python major version.")

        return phantom.APP_SUCCESS

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param python_version: Information of the Python version
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_msg = "Unknown error occurred. Please check the asset configuration and|or the action parameters."

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = "Error code unavailable"
                    error_msg = e.args[0]
            else:
                error_code = "Error code unavailable"
                error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
        except:
            error_code = "Error code unavailable"
            error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except:
            error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."

        return error_code, error_msg

    def _clean_empty_response(self, response):
        # PAPP-2087 DomainTools - Reverse Email table widget shows contextual action for no domain
        if response.get('domains') == []:
            del response['domains']

    def _parse_response(self, action_result, r, response_json):
        """
        No need to do exception handling, since this function call has a try...except around it.
        If you do want to catch a specific exception to generate proper error strings, go ahead
        """

        status = r.status_code
        response = response_json.get('response')
        error = response_json.get('error', {})

        if status == 400:
            error_message = 'You must include at least one search parameter from the list: domain, ip, email, ' \
                            'email_domain, nameserver_host, nameserver_domain, nameserver_ip, registrar, registrant, ' \
                            'registrant_org, mailserver_host, mailserver_domain, mailserver_ip, redirect_domain, ' \
                            'ssl_hash, ssl_subject, ssl_email, ssl_org, google_analytics, adsense, asn, isp_name, ' \
                            'search_hash'
            action_result.add_data({})
            return action_result.set_status(phantom.APP_ERROR, error_message)

        if status == 403:
            error_message = 'The credentials you entered do not match an active account'
            action_result.add_data({})
            return action_result.set_status(phantom.APP_ERROR, error_message)

        if status == 404:
            action_result.add_data({})
            return action_result.set_status(phantom.APP_ERROR,
                                            error.get('message', 'Domain Tools failed to find IP/Domain'))

        if status == 503:
            error_message = error.get('message', "There was an error processing your request. Please try again or contact support (http://www.domaintools.com/support) with questions.")
            action_result.add_data({})
            return action_result.set_status(phantom.APP_ERROR, error_message)

        if (status == 200) and (response):
            self._clean_empty_response(response)

            if 'results' in response:
                action_result.update_summary({'Connected Domains Count': len(response['results'])})
                action_result.update_data(response['results'])
            else:
                action_result.add_data(response)

            if response['limit_exceeded']:
                msg = response['message']
                action_result.update_summary({'Error': msg})
                return action_result.set_status(phantom.APP_ERROR, msg)

            return action_result.set_status(phantom.APP_SUCCESS)

        return action_result.set_status(phantom.APP_ERROR,
                                        error.get('message', 'An unknown error occurred while querying domaintools'))

    def _do_query(self, endpoint, action_result, data=None):
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
        url_params = "?"
        for k, search in data.items():
            url_params = "{}&{}={}".format(url_params, k, search)

        get = True
        if url_params != "?":
            url = "{}{}".format(url, url_params)
            if len(url_params) > 2000:
                get = False

        if get:  # We only want to use POST if we absolutely have to.
            try:
                self.save_progress("GET: {}".format(url))
                r = requests.get(url)
            except Exception as e:
                error_code, error_msg = self._get_error_message_from_exception(e)
                if error_code == "ascii":
                    error_msg = "Unicode value found. Please enter the valid input."
                return action_result.set_status(phantom.APP_ERROR, "REST API failed. Error Code: {0}. Error Message: {1}".format(error_code, error_msg))
        else:
            try:
                self.save_progress("POST: {} body: {}".format(url, data))
                r = requests.post(url, data=data)
            except Exception as e:
                error_code, error_msg = self._get_error_message_from_exception(e)
                if error_code == "ascii":
                    error_msg = "Unicode value found. Please enter the valid input."
                return action_result.set_status(phantom.APP_ERROR, "REST API failed. Error Code: {0}. Error Message: {1}".format(error_code, error_msg))

        self.save_progress("Parsing response...")
        try:
            response_json = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as a valid JSON", e)

        self.debug_print(r.url)

        # Now parse and add the response into the action result
        try:
            return self._parse_response(action_result, r, response_json)
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
            action_result.set_status(phantom.APP_ERROR, message, e)
            return action_result.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, 'Successfully connected to domaintools.com.\nTest Connectivity passed')

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        # Get the config
        config = self.get_config()

        self._ssl = config.get('ssl', False)
        self.save_progress("Username:", self._handle_py_ver_compat_for_input_str(config['username']))
        self._username = self._handle_py_ver_compat_for_input_str(config['username'])
        # self._username = config['username'].encode('utf-8')
        self._key = config['key'].encode('utf-8')

        if action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity()
        elif action_id == self.ACTION_ID_DOMAIN_ENRICH:
            ret_val = self._domain_enrich(param)
        elif action_id == self.ACTION_ID_DOMAIN_REPUTATION:
            ret_val = self._domain_reputation(param)
        elif action_id == self.ACTION_ID_PIVOT:
            ret_val = self._pivot_action(param)
        elif action_id == self.ACTION_ID_REVERSE_IP:
            updates = {'pivot_type': 'ip', 'query_value': param['ip'], 'ip': param['ip']}
            param.update(updates)
            ret_val = self._pivot_action(param)
        elif action_id == self.ACTION_ID_REVERSE_EMAIL:
            updates = {'pivot_type': 'email', 'query_value': param['email'], 'email': param['email']}
            param.update(updates)
            ret_val = self._pivot_action(param)
        elif action_id == self.ACTION_ID_REVERSE_DOMAIN:
            ret_val = self._reverse_domain(param)
        elif action_id == self.ACTION_ID_LOAD_HASH:
            data = {'pivot_type': 'search_hash', 'query_value': param['hash'], 'hash': param['hash']}
            param.update(data)
            ret_val = self._pivot_action(param)

        return ret_val

    def _reverse_domain(self, param):
        action_result = self.add_action_result(ActionResult(param))
        params = {'domain': self._handle_py_ver_compat_for_input_str(param.get('domain'))}
        ret_val = self._do_query('iris-investigate', action_result, data=params)

        if not ret_val:
            return action_result.get_data()

        data = action_result.get_data()

        if not data:
            return action_result.get_status()

        ips = []

        for a in data[0]['ip']:
            if 'address' in a:
                ips.append( { 'ip': a['address']['value'], 'type': 'Host IP', 'count': a['address']['count']  } )

        for a in data[0]['mx']:
            if 'ip' in a:
                for b in a['ip']:
                    ips.append( { 'ip': b['value'], 'type': 'MX IP', 'count': b['count']  } )

        for a in data[0]['name_server']:
            if 'ip' in a:
                for b in a['ip']:
                    ips.append( { 'ip': b['value'], 'type': 'NS IP', 'count': b['count']  } )

        action_result.update_summary({'ip_list': ips })

        return action_result.get_status()

    def _domain_enrich(self, param):
        action_result = self.add_action_result(ActionResult(param))
        domain_name = self._handle_py_ver_compat_for_input_str(param.get('domain'))
        params = {'domain': domain_name}
        return self._do_domain_enrich(action_result, params)

    def _do_domain_enrich(self, action_result, params):
        self._do_query('iris-investigate', action_result, data=params)
        return action_result.get_status()

    def _domain_reputation(self, param):

        action_result = self.add_action_result(ActionResult(param))
        domain_to_query = self._handle_py_ver_compat_for_input_str(param['domain'])
        params = {'domain': domain_to_query}

        ret_val = self._do_query('iris-investigate', action_result, data=params)

        if not ret_val:
            return action_result.get_data()

        data = action_result.get_data()

        if not data:
            return action_result.get_status()

        action_result.update_summary({'domain_risk': data[0]['domain_risk']['risk_score']})

        for a in data[0]['domain_risk']['components']:
            if(a['name'] == "whitelist"):
              action_result.update_summary({'is_whitelisted': True})
            else:
              action_result.update_summary({a['name']: a['risk_score']})

        return action_result.get_status()

    def _pivot_action(self, param):
        action_result = self.add_action_result(ActionResult(param))

        query_field = param['pivot_type']
        query_value = self._handle_py_ver_compat_for_input_str(param['query_value'])

        params = {query_field: query_value}

        if 'tld' in param:
            params['tld'] = self._handle_py_ver_compat_for_input_str(param['tld'])

        if 'data_updated_after' in param:
            params['data_updated_after'] = self._handle_py_ver_compat_for_input_str(param['data_updated_after'])
            if params['data_updated_after'].lower() == 'today':
                params['data_updated_after'] = datetime.today().strftime('%Y-%m-%d')
            if params['data_updated_after'].lower() == 'yesterday':
                params['data_updated_after'] = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')

        if 'create_date' in param:
            params['create_date'] = self._handle_py_ver_compat_for_input_str(param['create_date'])
            if params['create_date'].lower() == 'today':
                params['create_date'] = datetime.today().strftime('%Y-%m-%d')
            if params['create_date'].lower() == 'yesterday':
                params['create_date'] = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')

        if 'expiration_date' in param:
            params['expiration_date'] = self._handle_py_ver_compat_for_input_str(param['expiration_date'])
            if params['expiration_date'].lower() == 'today':
                params['expiration_date'] = datetime.today().strftime('%Y-%m-%d')
            if params['expiration_date'].lower() == 'yesterday':
                params['expiration_date'] = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')

        if 'status' in param and param['status'].lower() != 'any':
            params['active'] = 'true' if param['status'].lower() == 'active' else 'false'

        ret_val = self._do_query('iris-investigate', action_result, data=params)

        if not ret_val:
            return action_result.get_data()

        return action_result.get_status()


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = DomainToolsConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = DomainToolsConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
