# --
# File: ./reversinglabs/reversinglabs_view.py
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


def file_reputation(provides, all_results, context):

    print all_results
    results = []
    parameters = {}

    for summary, action_results in all_results:
        if not summary or not action_results:
            continue

        try:
            result = action_results[0].get_data()[0]
        except:
            result = {}
        try:
            result_summary = action_results[0].get_summary()
        except:
            result_summary = {}

        if 'a1000_report_url' in result_summary:
            parameters['a1000_link'] = result_summary["a1000_report_url"]
        else:
            parameters['a1000_link'] = 'http://www.reversinglabs.com'

        if 'threat_level' in result:
            parameters['threat_level'] = result["threat_level"]
        else:
            parameters['threat_level'] = "Check A1000 report"

        if 'trust_factor' in result:
            parameters['trust_factor'] = result["trust_factor"]
        else:
            parameters['trust_factor'] = "Check A1000 report"

        if 'threat_status' in result:
            parameters['status'] = result["threat_status"] #str_class[report['classification']['classification']]
        else:
            parameters['status'] = "Analyzed"

        parameters['scanners'] = "Please click A1000 link to view the report"





    context['parameters'] = parameters
    context['results'] = results
    context['title_text_color'] = 'white'
    context['body_color'] = '#0F75BC'
    context['title_color'] = 'white'
    return 'reversinglabs_template.html'
