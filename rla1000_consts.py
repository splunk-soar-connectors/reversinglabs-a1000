# --
# File: a1000_consts.py
#
# Copyright (c) ReversingLabs Inc 2016-2018
#
# This unpublished material is proprietary to ReversingLabs Inc.
# All rights reserved.
# Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of ReversingLabs Inc.
#
# --

A1000_JSON_BASE_URL = "base_url"
A1000_JSON_TASK_ID = "task_id"
A1000_JSON_API_KEY = "api_key"
A1000_JSON_MALWARE = "malware"
A1000_JSON_TASK_ID = "id"
A1000_JSON_VAULT_ID = "vault_id"
A1000_JSON_URL = "url"
A1000_JSON_HASH = "hash"
A1000_JSON_PLATFORM = "platform"
A1000_JSON_POLL_TIMEOUT_MINS = "timeout"

A1000_ERR_UNABLE_TO_PARSE_REPLY = "Unable to parse reply from device"
A1000_ERR_REPLY_FORMAT_KEY_MISSING = "None '{key}' missing in reply from device"
A1000_ERR_REPLY_NOT_SUCCESS = "REST call returned '{status}'"
A1000_SUCC_REST_CALL_SUCCEEDED = "REST Api call succeeded"
A1000_ERR_REST_API = "REST Api Call returned error, status_code: {status_code}, detail: {detail}"

A1000_TEST_PDF_FILE = "a1000_test_connectivity.pdf"
A1000_SLEEP_SECS = 3
A1000_MSG_REPORT_PENDING = "Report Not Found"
A1000_MSG_MAX_POLLS_REACHED = "Reached max polling attempts. Please use the MD5 or Sha256 of the file as a parameter to <b>get report</b> to query the report status."
A1000_PARAM_LIST = {
    "fields": [
        "id",
        "sha256",
        "category",
        "file_type",
        "file_subtype",
        "identification_name",
        "identification_version",
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
        "ticore",
        "ticloud",
        "aliases",
        "summary"]
}
# in minutes
A1000_MAX_TIMEOUT_DEF = 10
