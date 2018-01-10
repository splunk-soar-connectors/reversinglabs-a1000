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
    str_class = ['Unknown', 'Known', 'Suspicious', 'Malicious']
    # report[0]['data'][0]['task_info']['report'][0]['classification']
    for summary, action_results in all_results:
        print "summary " + str(summary) + " action_results " + str(action_results)
        if not summary or not action_results:
            continue
        for result in action_results:
            parameter = result.get_param()
            result_summary = result.get_summary()
            print "result " + str(result_summary) + " parameter " + str(parameter)
            for dataelem in result.get_data():
                # print " ***************************** data element  : " + str(dataelem) + "****************************"
                if 'a1000_link' in dataelem:
                    print "++++++++++++++++++++ a1000_link +++++++++++++++ :" + dataelem['a1000_link']
                    parameters['a1000_link'] = dataelem['a1000_link']
                if 'task_info' in dataelem:
                    print " ***************************** task_info  ***************************"
                    for report in dataelem['task_info']['report']:
                        if 'classification' in report:
                            print "++++++++++++++++++++ classification +++++++++++++++ :" + str(report['classification'])
                            if 'threat_factor' in report['classification']:
                                parameters['threat_factor'] = report['classification']['threat_factor']
                            else:
                                parameters['threat_factor'] = " Check A1000 report "
                            if 'status' in report['classification']:
                                parameters['status'] = str_class[report['classification']['classification']]
                            else:
                                parameters['status'] = " Analyzed "
                            # put together the scan results
                            scan_results = " Please click A1000 link to view the report "
                            if 'scan_results' in report['classification']:
                                for scan in report['classification']['scan_results']:
                                    scan_results = scan_results + "Classifier " + scan['name'] + " found threat named "
                                    scan_results = scan_results + scan['result'] + " with threat factor " + str(scan['threat_factor'])
                                    scan_results = scan_results + " and marked file as " + str_class[scan['classification']] + ". \n"
                            parameters['scanners'] = scan_results
                            print str(parameters)
    context['parameters'] = parameters
    context['results'] = results
    context['title_text_color'] = 'white'
    context['body_color'] = '#0F75BC'
    context['title_color'] = 'white'
    return 'reversinglabs_template.html'
