# File: rla1000_connector.py
#
# Copyright (c) 2016-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#

# Phantom imports
import phantom.app as phantom
import phantom.rules as ph_rules
from phantom.app import ActionResult, BaseConnector

try:
    from phantom.vault import Vault
except BaseException:
    import phantom.vault as Vault

import inspect
import json
# Other imports used by this connector
import os
import re
import time

# import xmltodict
import requests
from bs4 import BeautifulSoup
from requests import ConnectionError, HTTPError
# Wheels import
from rl_threat_hunting import child_evaluation, file_report, local, local_reputation, tc_metadata_adapter

from rla1000_consts import *


class RetVal(tuple):
    """Represent a class to create a tuple."""

    def __new__(cls, val1, val2=None):
        """Create a tuple from the provided values."""
        return tuple.__new__(RetVal, (val1, val2))


class A1000Connector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_DETONATE_FILE = "detonate_file"
    ACTION_ID_GET_REPORT = "get_report"
    ACTION_ID_REANALYZE_FILE = "reanalyze_file"
    ACTION_ID_TEST_ASSET_CONNECTIVITY = 'test_asset_connectivity'
    ACTION_ID_ADVANCED_SEARCH = 'local_adv_search'

    MAGIC_FORMATS = [
      (re.compile('^PE.* Windows'), ['pe file'], '.exe'),
      (re.compile('^MS-DOS executable'), ['pe file'], '.exe'),
      (re.compile('^PDF '), ['pdf'], '.pdf'),
      (re.compile('^MDMP crash'), ['process dump'], '.dmp'),
      (re.compile('^Macromedia Flash'), ['flash'], '.flv'),
      (re.compile('^tcpdump capture'), ['pcap'], '.pcap'),
    ]

    FILE_UPLOAD_ERROR_DESC = {
            '401': 'API key invalid',
            '405': 'HTTP method Not Allowed',
            '413': 'Sample file size over max limit',
            '418': 'Sample file type is not supported',
            '419': 'Max number of uploads per day exceeded',
            '422': 'URL download error',
            '500': 'Internal error',
            '513': 'File upload failed'}

    GET_REPORT_ERROR_DESC = {
            '401': 'API key invalid',
            '404': 'The report was not found',
            '405': 'HTTP method Not Allowed',
            '419': 'Request report quota exceeded',
            '420': 'Insufficient arguments',
            '421': 'Invalid arguments',
            '500': 'Internal error'}

    GET_SAMPLE_ERROR_DESC = {
            '401': 'API key invalid',
            '403': 'Permission Denied',
            '404': 'The sample was not found',
            '405': 'HTTP method Not Allowed',
            '419': 'Request sample quota exceeded',
            '420': 'Insufficient arguments',
            '421': 'Invalid arguments',
            '500': 'Internal error'}

    PLATFORM_ID_MAPPING = {
            'Default': None,
            'Win XP, Adobe 9.3.3, Office 2003': 1,
            'Win XP, Adobe 9.4.0, Flash 10, Office 2007': 2,
            'Win XP, Adobe 11, Flash 11, Office 2010': 3,
            'Win 7 32-bit, Adobe 11, Flash11, Office 2010': 4,
            'Win 7 64 bit, Adobe 11, Flash 11, Office 2010': 5,
            'Android 2.3, API 10, avd2.3.1': 201}

    def __init__(self):

        # Call the BaseConnectors init first
        super(A1000Connector, self).__init__()

        self._api_token = None

    def initialize(self):

        config = self.get_config()

        # Base URL
        self._base_url = config[A1000_JSON_BASE_URL]
        if (self._base_url.endswith('/')):
            self._base_url = self._base_url[:-1]

        self._host = self._base_url[self._base_url.find('//') + 2:]

        # self._req_sess = requests.Session()

        self._search_url = "{}{}".format(self._base_url, ADVANCED_SEARCH_API_URL)

        return phantom.APP_SUCCESS

    def _validate_integer(self, action_result, parameter, key):
        """
        Validate an integer.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, integer value of the parameter or None in case of failure
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return (
                        action_result.set_status(phantom.APP_ERROR, A1000_VALID_INT_MSG.format(param=key)),
                        None,
                    )

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, A1000_VALID_INT_MSG.format(param=key)), None

            # Negative value validation
            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, A1000_NON_NEG_INT_MSG.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.

        :param e: Exception object
        :return: error message
        """
        error_code = None
        error_msg = ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception:
            pass

        if not error_code:
            error_text = "Error Message: {}".format(error_msg)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

        return error_text

    def _parse_error(self, response, result, error_desc):

        status_code = response.status_code
        detail = response.text

        if (detail):
            return result.set_status(
                phantom.APP_ERROR,
                A1000_ERR_REST_API.format(
                    status_code=status_code,
                    detail=json.loads(detail)['message']))

        if (not error_desc):
            return result.set_status(
                phantom.APP_ERROR, A1000_ERR_REST_API.format(
                    status_code=status_code, detail='N/A'))

        detail = error_desc.get(str(status_code))

        if (not detail):
            # no detail
            return result.set_status(
                phantom.APP_ERROR, A1000_ERR_REST_API.format(
                    status_code=status_code, detail='N/A'))

        return result.set_status(
            phantom.APP_ERROR,
            A1000_ERR_REST_API.format(
                status_code=status_code,
                detail=detail))

    def _process_empty_response(self, response, action_result):
        """
        Process empty response.

        :param response: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        if response.status_code == 200 or response.status_code == 204:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, A1000_ERR_EMPTY_RESPONSE.format(code=response.status_code)
            ),
            None,
        )

    def _process_html_response(self, response, action_result):
        """
        Process html response.

        :param response: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = A1000_UNABLE_TO_PARSE_ERR_DETAIL

        if not error_text:
            error_text = "Empty response and no information received"
        message = "Status Code: {}. Data from server: {}".format(status_code, error_text)

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        """
        Process json response.

        :param r: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        status_code = r.status_code
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, A1000_ERR_UNABLE_TO_PARSE_JSON_RESPONSE.format(error=error_msg)
                ),
                None,
            )

        errors = resp_json.get("errors", [])
        if errors and isinstance(errors, list):
            try:
                error_msg = ". ".join([error.get("message") for error in errors if error.get("message")])
                if error_msg:
                    message = "Error from server. Status Code: {}. Error Details: {}".format(status_code, error_msg)
                    return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)
            except Exception:
                pass

        # Please specify the status codes here
        if 200 <= r.status_code < 300:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        if resp_json.get("name") and resp_json.get("message"):
            message = "Error from server. Error Code: {}. Error Message: {}".format(
                resp_json["name"], resp_json["message"]
            )
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        # You should process the error returned in the json
        error_text = r.text.replace("{", "{{").replace("}", "}}")
        message = "Error from server. Status Code: {}. Data from server: {}".format(status_code, error_text)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        """
        Process API response.

        :param r: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        error_text = r.text.replace("{", "{{").replace("}", "}}")
        message = "Can't process response from server. Status Code: {} Data from server: {}".format(
            r.status_code, error_text
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(
            self,
            endpoint,
            result,
            error_desc,
            method="get",
            params={},
            data={},
            filein=None,
            files=None,
            parse_response=True,
            additional_succ_codes={}):

        url = "{0}{1}".format(self._base_url, endpoint)

        config = self.get_config()

        if (files is None):
            files = dict()

        if (filein is not None):
            files = {'file': filein}

        # request_func = getattr(self._req_sess, method)

        # if (not request_func):
        # return (result.set_status(phantom.APP_ERROR, "Invalid method call: {0}
        # for requests module".format(method)), None)

        if method == 'post':
            try:
                r = requests.post(
                    url,
                    timeout=10,
                    data=data,
                    files=files,
                    verify=config[phantom.APP_JSON_VERIFY],
                    headers={'Authorization': 'Token %s' % config[A1000_JSON_API_KEY],
                    'User-Agent': 'ReversingLabs Phantom A1000 v2.2'})
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return result.set_status(phantom.APP_ERROR, "REST Api to server failed {}".format(err)), None
        else:
            try:
                r = requests.get(
                    url,
                    timeout=10,
                    verify=config[phantom.APP_JSON_VERIFY],
                    headers={'Authorization': 'Token %s' % config[A1000_JSON_API_KEY], 'User-Agent': 'ReversingLabs Phantom A1000 v2.2'})
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return result.set_status(phantom.APP_ERROR, "REST Api to server failed {}".format(err)), None

        # It's ok if r.text is None, dump that
        if (hasattr(result, 'add_debug_data')):
            result.add_debug_data({'r_text': r.text if r else 'r is None'})

        if (r.status_code in additional_succ_codes):
            response = additional_succ_codes[r.status_code]
            return phantom.APP_SUCCESS, response

        if (not parse_response):
            return phantom.APP_SUCCESS, r

        return self._process_response(r, result)

    def _get_file_dict(self, param, action_result):

        vault_id = param[A1000_JSON_VAULT_ID]

        filename = param.get('file_name')
        if not filename:
            filename = vault_id

        try:
            success, msg, files_array = ph_rules.vault_info(vault_id=vault_id)
            if not success:
                return (action_result.set_status(phantom.APP_ERROR,
                        f'Unable to get Vault item details. Error Details: {msg}'),
                        None)
            file_data = list(files_array)[0]
            with open(file_data['path'], 'rb') as f:
                payload = f.read()

        except BaseException:
            return (
                action_result.set_status(
                    phantom.APP_ERROR,
                    'File not found in vault ("{}")'.format(vault_id)),
                None)

        files = {'file': (filename, payload)}

        return (phantom.APP_SUCCESS, files)

    def _test_connectivity(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        # get the file from the app directory
        dirpath = os.path.dirname(inspect.getfile(self.__class__))
        filename = A1000_TEST_PDF_FILE

        filepath = "{}/{}".format(dirpath, filename)

        try:
            payload = open(filepath, 'rb')
        except BaseException:
            action_result.set_status(phantom.APP_ERROR,
                            'Test pdf file not found at "{}"'.format(filepath))
            action_result.append_to_message('Test Connectivity failed')
            return action_result.get_status()

        try:
            self.save_progress(
                'Detonating test pdf file for checking connectivity')
            files = payload
            ret_val, response = self._make_rest_call(
                '/api/uploads/', action_result, self.FILE_UPLOAD_ERROR_DESC,
                method='post', filein=files)
            payload.close()
        except BaseException:
            action_result.set_status(
                phantom.APP_ERROR,
                'Connectivity failed, check the server name and API key.')
            action_result.append_to_message('Test Connectivity Failed.')
            return action_result.get_status()

        if (phantom.is_fail(ret_val)):
            action_result.append_to_message('Test Connectivity Failed')
            return action_result.get_status()

        return action_result.set_status(
            phantom.APP_SUCCESS, 'Test Connectivity Passed')

    def _normalize_into_list(self, input_dict, key):
        if (not input_dict):
            return None

        if (key not in input_dict):
            return None

        if (type(input_dict[key] != list)):
            input_dict[key] = [input_dict[key]]
        input_dict[key.lower()] = input_dict.pop(key)

        return input_dict

    def _normalize_children_into_list(self, input_dict):

        if (not input_dict):
            return {}

        for key in list(input_dict.keys()):
            if (not isinstance(input_dict[key], list)):
                input_dict[key] = [input_dict[key]]
            input_dict[key.lower()] = input_dict.pop(key)

        return input_dict

    def _check_detonated_report(self, task_id, action_result, threat_hunting_state=None):
        """This function is different than other functions that get the report
        since it is supposed to check just once and return, also treat a 404 as error
        """

        data = {'hash_values': [task_id], 'fields': A1000_PARAM_LIST['fields']}

        success, ticloud_response = self._make_rest_call(
            '/api/samples/%s/ticloud/' % task_id, action_result, self.GET_REPORT_ERROR_DESC,
            method='get',
            additional_succ_codes={404: A1000_MSG_REPORT_PENDING})

        ticore_success, ticore_response = self._make_rest_call(
            '/api/samples/%s/ticore/' % task_id, action_result, self.GET_REPORT_ERROR_DESC,
            method='get',
            additional_succ_codes={404: A1000_MSG_REPORT_PENDING})

        # ticore extracted
        ef_success, ef_response = self._make_rest_call(
            '/api/samples/%s/extracted-files/' % task_id, action_result, self.GET_REPORT_ERROR_DESC,
            method='get',
            additional_succ_codes={404: A1000_MSG_REPORT_PENDING})
        hunting_meta = self._parse_hunting_meta_on_success(
            ticore_success, ticore_response, ef_success, ef_response, threat_hunting_state)

        success, summary_data = self._make_rest_call(
            '/api/samples/list/', action_result, self.GET_REPORT_ERROR_DESC, data=data,
            method='post',
            additional_succ_codes={404: A1000_MSG_REPORT_PENDING})

        if summary_data is not None and 'count' in summary_data and summary_data['count'] > 0:
            summary_data = summary_data['results'][0]
            if "story" in ticore_response:
                summary_data["story"] = ticore_response["story"]

            # remove hashes other than sha1
            if summary_data is not None:
                if 'classification_origin' in summary_data:
                    if summary_data['classification_origin'] is not None:
                        if 'sha1' in summary_data['classification_origin']:
                            summary_data['classification_origin'] = {'sha1': summary_data['classification_origin']['sha1']}

        return {"ticloud": ticloud_response}, {"ticore": [ticore_response, ef_response]}, hunting_meta, summary_data

        # parse if successfull
        # response = self._parse_report_status_msg(response, action_result, data)

        # if (response):
        #    return (phantom.APP_SUCCESS, response)

        # return (phantom.APP_ERROR, None)

    def _parse_hunting_meta_on_success(self, ticore_success, ticore_response, extracted_success, extracted_files, threat_hunting_state=None):
        if ticore_success != phantom.APP_SUCCESS or isinstance(ticore_response, str):
            return {}

        ticore_response = local_reputation.process_local_reputation(self._make_local_file_reputation_request, [
                                                                    ticore_response], threat_hunting_state)
        ticore_response = ticore_response[0]

        if extracted_success == phantom.APP_SUCCESS:
            interesting_children = child_evaluation.a1000_select_interesting_extracted_files(
                extracted_files, interesting_child_limit=25)
            enriched_children = child_evaluation.a1000_fetch_child_metadata(self._fetch_tc_report, interesting_children)
            enriched_children = local_reputation.process_local_reputation(
                self._make_local_file_reputation_request, enriched_children)
            ticore_response = child_evaluation.a1000_combine_container_and_children(ticore_response, enriched_children)

        return tc_metadata_adapter.parse_tc_metadata(ticore_response, threat_hunting_state)

    def _fetch_tc_report(self, sample_sha1):
        endpoint = '{}/api/samples/{}/ticore/'.format(self._base_url, sample_sha1)
        config = self.get_config()
        response = requests.get(endpoint,
                                timeout=10,
                                headers={'Authorization': 'Token %s' % config[A1000_JSON_API_KEY],
                                    'User-Agent': 'ReversingLabs Phantom A1000 v2.2'},
                                verify=config[phantom.APP_JSON_VERIFY])
        response.raise_for_status()
        return response.json()

    def _make_local_file_reputation_request(self, hash_values):
        endpoint = '{}/api/samples/list/details/'.format(self._base_url)
        post_data = {
            'hash_values': hash_values,
            'fields': A1000_SAMPLE_DETAILS,
        }
        config = self.get_config()
        response = requests.post(endpoint,
                                timeout=10,
                                data=json.dumps(post_data),
                                headers={'Authorization': 'Token %s' % config[A1000_JSON_API_KEY],
                                         'Content-Type': 'application/json',
                                         'User-Agent': 'ReversingLabs Phantom A1000 v2.2'},
                                verify=config[phantom.APP_JSON_VERIFY])
        response.raise_for_status()
        return response.json()

    def _poll_task_status(self, task_id, action_result):
        polling_attempt = 0

        config = self.get_config()

        timeout = config[A1000_JSON_POLL_TIMEOUT_MINS]
        ret_val, timeout = self._validate_integer(
            action_result, timeout, "timeout"
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if (not timeout):
            timeout = A1000_MAX_TIMEOUT_DEF

        max_polling_attempts = (timeout * 60) / A1000_SLEEP_SECS

        data = {'hash_values': [task_id]}

        while (polling_attempt < max_polling_attempts):

            polling_attempt += 1

            self.save_progress(
                "Polling attempt {0} of {1}".format(
                    polling_attempt,
                    max_polling_attempts))

            ret_val, response = self._make_rest_call(
                '/api/samples/status/', action_result, self.GET_REPORT_ERROR_DESC,
                method='post', data=data,
                additional_succ_codes={404: A1000_MSG_REPORT_PENDING})

            if (phantom.is_fail(ret_val)):
                return (action_result.get_status())

            # if results not processed postpone
            if ("results" in response and len(response["results"]) > 0):
                if response["results"][0].get("status") != "processed":
                    time.sleep(A1000_SLEEP_SECS)
                    continue
                else:
                    return True

        self.save_progress("Reached max polling attempts")
        return False

        # return (action_result.set_status(phantom.APP_ERROR,A1000_MSG_MAX_POLLS_REACHED),None)

    def _get_report(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        task_id = param[A1000_JSON_VAULT_ID]

        ret_val = self.add_report(action_result, task_id)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # action_result.set_summary(summary)
        # The next part is the report
        # data.update(response['results'][0])

        # malware = data.get('file_info', {}).get('malware', 'no')

        # action_result.update_summary({A1000_JSON_MALWARE: malware})

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully executed the get report action")

    def _reanalyze_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        vault_id = param[A1000_JSON_VAULT_ID]  # sha1

        data = {'analysis': 'cloud'}
        # data = {'hash_value': [vault_id], 'analysis': 'cloud'}

        ret_val, response = self._make_rest_call(
            '/api/samples/%s/analyze/' % vault_id, action_result, self.GET_REPORT_ERROR_DESC,
            method='post', data=data,
            additional_succ_codes={404: "File not found and could not be queued for analysis"})

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Set summary
        try:
            result = {"Response": response['message']}
            data = action_result.add_data(result)
            action_result.set_summary(result)
        except BaseException:
            data = action_result.add_data({'response': response})
            action_result.set_summary({'response': response})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_platform_id(self, param):

        platform = param.get(A1000_JSON_PLATFORM)

        if (not platform):
            return None

        platform = platform.upper()

        if (platform not in self.PLATFORM_ID_MAPPING):
            return None

        return self.PLATFORM_ID_MAPPING[platform]

    def validate_parameters(self, param):
        """Do our own validations instead of BaseConnector doing it for us"""

        return phantom.APP_SUCCESS

    def _get_vault_file_sha256(self, vault_id, action_result):

        self.save_progress('Getting the sha256 of the file')

        sha256 = None
        metadata = None

        try:
            success, msg, files_array = ph_rules.vault_info(vault_id=vault_id)
            if not success:
                return action_result.set_status(phantom.APP_ERROR,
                            f'Unable to get Vault item details. Error Details: {msg}'), None
            file = list(files_array)[0]
            metadata = file['metadata']
        except BaseException:
            return action_result.set_status(
                    phantom.APP_ERROR,
                    'File not found in vault ("{}")'.format(vault_id)), None

        try:
            sha256 = metadata['sha256']
        except Exception as e:
            self.debug_print('Handled exception {}'.format(self._get_error_message_from_exception(e)))
            return (
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to get meta info of vault file {}".format(metadata)),
                None)

        return (phantom.APP_SUCCESS, sha256)

    def add_report(self, action_result, task_id, threat_hunting_state=None):
        # Add the report
        try:
            # Now poll for the result
            try:
                ticloud, ticore, hunting_meta, summary_data = self._check_detonated_report(
                    task_id, action_result, threat_hunting_state)
            except Exception:
                action_result.add_data({"test0": "fail"})

            # ret_val, response = self._poll_task_status(task_id, action_result)

            if ticloud["ticloud"]:
                action_result.add_data(ticloud)
            else:
                action_result.add_data({"ticloud": "result not found"})
            if ticore["ticore"][0]:
                action_result.add_data(ticore)
            else:
                action_result.add_data({"ticore": "result not found"})
            if hunting_meta:
                hunting_meta_vault_id = self._store_threat_hunting_state(hunting_meta)
                self._update_threat_hunting_state(action_result, hunting_meta, hunting_meta_vault_id)
            else:
                action_result.add_data({A1000_JSON_HUNTING_STATE: 'does not exist'})
                return action_result.set_status(phantom.APP_ERROR, "Could not execute the action. No data found.")

        except BaseException:
            return action_result.set_status(phantom.APP_ERROR, "Failed to update data stage 2")
        return phantom.APP_SUCCESS

    def _detonate_file(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, files = self._get_file_dict(param, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        ret_val, threat_hunting_state, vault_id = self._get_threat_hunting_state(param, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # get the sha256 of the file
        vault_id = param[A1000_JSON_VAULT_ID]
        ret_val, sha256 = self._get_vault_file_sha256(vault_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        data = action_result.add_data({})
        self.save_progress('Checking for prior detonations for {} sha256 {}'.format(vault_id, sha256))

        try:
            # check if there is existing report already
            ticloud, ticore, hunting_meta, summary_data = self._check_detonated_report(vault_id, action_result, threat_hunting_state)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

        # report does not exist yet
        if ticloud["ticloud"] == "Report Not Found" or ticore["ticore"] == "Report Not Found":

            # Was not detonated before
            self.save_progress('Uploading the file')

            # upload the file to the upload service
            ret_val, response = self._make_rest_call(
                '/api/uploads/', action_result, self.FILE_UPLOAD_ERROR_DESC,
                method='post', filein=files['file'][1])

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            # get the sha1
            task_id = response.get('sha1')
            if task_id is None:
                task_id = response.get('detail').get('sha1')

            # Now poll for the result
            finished = self._poll_task_status(task_id, action_result)

            if not finished:
                try:
                    ticloud, ticore, hunting_meta, summary_data = self._check_detonated_report(
                        task_id, action_result, threat_hunting_state)
                except Exception as e:
                    err = self._get_error_message_from_exception(e)
                    return action_result.set_status(phantom.APP_ERROR, err)

                if ticloud is not None:
                    data["ticloud"] = ticloud
                if ticore is not None:
                    data["ticore"] = ticore
                if hunting_meta is not None:
                    try:
                        hunting_meta_vault_id = self._store_threat_hunting_state(hunting_meta)
                    except Exception as e:
                        err = self._get_error_message_from_exception(e)
                        return action_result.set_status(phantom.APP_ERROR, err)
                    self._update_threat_hunting_state(action_result, hunting_meta, hunting_meta_vault_id)

                data.update(data)

            # Add the report
            try:
                polling_attempt = 0
                max_polling_attempts = 10
                try:
                    ticloud, ticore, hunting_meta, summary_data = self._check_detonated_report(
                        sha256, action_result, threat_hunting_state)
                    while (polling_attempt < max_polling_attempts and summary_data["threat_status"] == "unknown"):
                        ticloud, ticore, hunting_meta, summary_data = self._check_detonated_report(
                            task_id, action_result, threat_hunting_state)
                        polling_attempt += 1
                        time.sleep(1)
                except Exception as e:
                    err = self._get_error_message_from_exception(e)
                    return action_result.set_status(phantom.APP_ERROR, err)

                data = {"ticore": ticore, "ticloud": ticloud}
                data.update(data)

                hunting_meta_vault_id = self._store_threat_hunting_state(hunting_meta)
                self._update_threat_hunting_state(action_result, hunting_meta, hunting_meta_vault_id)
            except Exception as e:
                self.debug_print('Handled exception {}'.format(self._get_error_message_from_exception(e)))
                return (action_result.set_status(
                        phantom.APP_ERROR,
                        "Unable to get meta info of vault file"))

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

        ret_val = self.add_report(action_result, sha256, threat_hunting_state)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully executed the detonate file action")

    def _local_advanced_search(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, hunting_report, vault_id = self._get_threat_hunting_state(param, action_result)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        single_search_term = param.get(A1000_ADV_SEARCH)
        results_per_page = param.get("results_per_page")
        ret_val, results_per_page = self._validate_integer(
            action_result, results_per_page, "results_per_page"
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        page_number = param.get("page_number")
        ret_val, page_number = self._validate_integer(
            action_result, page_number, "page_number"
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            if hunting_report:
                self._hunting_with_advanced_search(action_result, hunting_report, vault_id)
            elif single_search_term:
               self._advanced_search_make_single_query(action_result, single_search_term, results_per_page, page_number)
            else:
                return action_result.set_status(phantom.APP_ERROR,
                "Please provide either '{}' or '{}'".format(A1000_JSON_HUNTING_STATE, A1000_ADV_SEARCH))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully executed the local advanced search action")

    def _hunting_with_advanced_search(self, action_result, hunting_report, vault_id):
        search_tasks = local.get_query_tasks(hunting_report)

        if not search_tasks:
            self._update_threat_hunting_state(action_result, hunting_report, vault_id)
            return

        for task in search_tasks:
            search_term = task['query']['term']

            if 'classification:' in search_term:
                search_function = self._make_search_api_request
            else:
                search_function = self._make_double_search_api_request

            try:
                api_data = search_function(search_term)
            except (HTTPError, ConnectionError):
                local.mark_tasks_as_failed(hunting_report, task)
                continue

            try:
                local.update_hunting_meta(hunting_report, api_data, task)
            except StopIteration:
                break

        hunting_meta_vault_id = self._store_threat_hunting_state(hunting_report)
        self._update_threat_hunting_state(action_result, hunting_report, hunting_meta_vault_id)

    def _make_double_search_api_request(self, task_term):
        api_data = tuple()
        for search_term in [task_term + ' AND classification:malicious',
                            task_term + ' AND classification:known']:
            response = self._make_search_api_request(search_term)
            api_data += (response,)
        return api_data

    def _advanced_search_make_single_query(self, action_result, search_term, results_per_page, page_number):
        api_data = self._make_search_api_request(search_term, results_per_page, page_number)
        if api_data:
            action_result.add_data(api_data)

    def _make_search_api_request(self, search_term, results_per_page, page_number):
        config = self.get_config()
        post_data = {'query': search_term, 'page': page_number or 1, 'records_per_page': results_per_page or MAX_SEARCH_RESULTS}
        response = requests.post(self._search_url,
                                timeout=10,
                                data=json.dumps(post_data),
                                verify=config[phantom.APP_JSON_VERIFY],
                                headers={'Authorization': 'Token %s' % config[A1000_JSON_API_KEY],
                                           'Content-Type': 'application/json',
                                           'User-Agent': 'ReversingLabs Phantom A1000 v2.2'}
                                 )

        if response.ok:
            return response.json()

        response.raise_for_status()

    @staticmethod
    def _get_threat_hunting_state(parameters, action_result):
        hunting_report_vault_id = parameters.get(A1000_JSON_HUNTING_STATE)
        if hunting_report_vault_id:
            try:
                success, msg, files_array = ph_rules.vault_info(vault_id=hunting_report_vault_id)
                if not success:
                    return action_result.set_status(phantom.APP_ERROR,
                        f'Unable to get Vault item details. Error Details: {msg}'), None, None
                file_data = list(files_array)[0]
                with open(file_data['path'], 'rb') as f:
                    payload = f.read()
                return phantom.APP_SUCCESS, json.loads(payload), hunting_report_vault_id

            except BaseException:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    'File not found in vault ("{}")'.format(hunting_report_vault_id)), None, None
        return phantom.APP_SUCCESS, None, None

    def _store_threat_hunting_state(self, hunting_meta):
        container_id = self.get_container_id()
        vault_file_name = self._create_hunting_report_name()
        dump_path = self._dump_report_in_file(hunting_meta, vault_file_name)
        success, message, vault_id = ph_rules.vault_add(container_id, dump_path, file_name=vault_file_name)

        if success:
            return vault_id
        else:
            raise VaultError('Storing threat hunting report failed: {}'.format(message))

    def _create_hunting_report_name(self):
        product_name = self._get_product_name()
        action_name = self._get_action_name()
        return '{}_{}_hunting_report.json'.format(product_name, action_name)

    def _get_product_name(self):
        app_config = self.get_app_json()
        product_name = app_config['product_name']
        return product_name.replace(' ', '_')

    def _get_action_name(self):
        action_name = self.get_action_name()
        return action_name.replace(' ', '_')

    @staticmethod
    def _dump_report_in_file(hunting_meta, file_name):
        dump_dir = Vault.get_vault_tmp_dir()
        dump_path = '{}/{}'.format(dump_dir, file_name)
        return file_report.write_json(hunting_meta, dump_path)

    @staticmethod
    def _update_threat_hunting_state(action_result, hunting_report, hunting_report_vault_id):
        action_result.add_data(hunting_report)
        action_result.add_data({A1000_JSON_HUNTING_STATE: hunting_report_vault_id})

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS
        # Get the action that we are supposed to execute for this connector run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_DETONATE_FILE):
            ret_val = self._detonate_file(param)
        elif (action_id == self.ACTION_ID_GET_REPORT):
            ret_val = self._get_report(param)
        elif (action_id == self.ACTION_ID_REANALYZE_FILE):
            ret_val = self._reanalyze_file(param)
        elif (action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        elif (action_id == self.ACTION_ID_ADVANCED_SEARCH):
            ret_val = self._local_advanced_search(param)
        return ret_val


class ApplicationExecutionFailed(Exception):
    pass


class VaultError(Exception):
    pass


if __name__ == '__main__':

    import sys

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = A1000Connector()
        connector.print_progress_message = True
        injson = json.dumps(in_json)
        ret_val = connector._handle_action(injson, None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
