# File: rla1000_consts.py
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

A1000_JSON_BASE_URL = "base_url"
A1000_JSON_API_KEY = "api_key"
A1000_JSON_MALWARE = "malware"
A1000_JSON_TASK_ID = "id"
A1000_JSON_VAULT_ID = "file_vault_id"
A1000_JSON_URL = "url"
A1000_JSON_HASH = "hash"
A1000_ADV_SEARCH = "search_parameter"
A1000_JSON_PLATFORM = "platform"
A1000_JSON_POLL_TIMEOUT_MINS = "timeout"
A1000_JSON_HUNTING_STATE = 'hunting_report_vault_id'

A1000_ERR_UNABLE_TO_PARSE_REPLY = "Unable to parse reply from device"
A1000_ERR_REPLY_FORMAT_KEY_MISSING = "None '{key}' missing in reply from device"
A1000_ERR_REPLY_NOT_SUCCESS = "REST call returned '{status}'"
A1000_SUCC_REST_CALL_SUCCEEDED = "REST Api call succeeded"
A1000_ERR_REST_API = "REST Api Call returned error, status_code: {status_code}, detail: {detail}"

A1000_TEST_PDF_FILE = "a1000_test_connectivity.pdf"
A1000_SLEEP_SECS = 3
A1000_MSG_REPORT_PENDING = "Report Not Found"
A1000_MSG_MAX_POLLS_REACHED = """Reached max polling attempts.
Please use the MD5 or Sha256 of the file as a parameter to <b>get report</b> to query the report status."""
# Constants relating to error messages
A1000_ERR_EMPTY_RESPONSE = "Status Code {code}. Empty response and no information in the header."
A1000_UNABLE_TO_PARSE_ERR_DETAIL = "Cannot parse error details"
A1000_ERR_UNABLE_TO_PARSE_JSON_RESPONSE = "Unable to parse response as JSON. {error}"
A1000_PARAM_LIST = {
    "fields": [
        "file_type",
        "file_subtype",
        "file_size",
        "extracted_file_count",
        "local_first_seen",
        "local_last_seen",
        "classification_origin",
        "classification_reason",
        "threat_status",
        "trust_factor",
        "threat_level",
        "threat_name",
        "summary"]
}
# in minutes
A1000_MAX_TIMEOUT_DEF = 10

ADVANCED_SEARCH_API_URL = '/api/samples/search/'
MAX_SEARCH_RESULTS = 1000

A1000_SAMPLE_DETAILS = [
    'sha1',
    'sha256',
    'md5',
    'classification_reason',
    'classification_source',
    'threat_status',
    'threat_name',
    'threat_level',
    'trust_factor',
    'av_scanners_summary',
    'local_first_seen',
    'local_last_seen',
]

# Constants relating to 'validate_integer'
A1000_VALID_INT_MSG = "Please provide a valid integer value in the '{param}' action parameter"
A1000_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the '{param}' action parameter"

# Constants relating to 'get_error_message_from_exception'
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
