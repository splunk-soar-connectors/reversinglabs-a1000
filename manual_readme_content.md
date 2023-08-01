[comment]: # " File: README.md"
[comment]: # "  Copyright (c) ReversingLabs Inc 2016-2022"
[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "      http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""
# ReversingLabs A1000 Malware Analysis Appliance

This app supports using ReversingLabs Advanced File Analysis to 'detonate file' on the A1000
Advanced Malware Analysis Appliance.  
  
The A1000 appliance is a powerful threat detection and file analysis platform that integrates other
ReversingLabs technologies (TitaniumCore - the automated static analysis solution, and TitaniumCloud
File Reputation Service) to provide detailed information on each file's status and threat
capabilities.  
  
The A1000 makes it easy to upload multiple samples for analysis. It can process, unpack, and
classify them in a matter of milliseconds, and display detailed analysis reports. Historical
analysis results are preserved in a database to enable in-depth searching, and malware samples are
continually reanalyzed to ensure the most up-to-date file reputation status.  
  
The A1000 relies on several threat classification methods, including YARA rules and ReversingLabs
hashing algorithm (RHA) that classifies files based on their functional similarity.  
  
For more information, consult the [official product
website.](https://www.reversinglabs.com/products/malware-analysis-appliance.html)

## How to Configure the App

Access the Asset Settings tab on the Asset Configuration page. The variables described in the
previous section are displayed in this tab.  
[![](img/rla1000_asset.png)](img/rla1000_asset.png)  
  
  
The "Base URL" field requires the host address of the A1000 appliance. Select the "Verify server
certificate" checkbox to allow only commercial certificates, not the self-signed certificates.  
  
  
The "API Key" contains the authentication token obtained from an A1000 instance used for accessing
the A1000 REST API.  
  
  
The "Detonate timeout" variable defines how long the app should wait for the results from the A1000
appliance.

**Playbook Backward Compatibility**

Below mentioned actions and parameters have been added. Hence, it is requested to the end-user to
please update their existing playbooks by re-inserting|adding|deleting the corresponding action
blocks or by providing appropriate values to these action parameters to ensure the correct
functioning of the playbooks created on the earlier versions of the app.

-   The "hunting_report_vault_id" parameter has been added in "detonate file" and "get report"
    action.
-   Added a new action "local advanced search" - The action will query A1000 instance with a
    specified Advanced Search query.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the RL A1000 Malware Analysis Appliance
server. Below are the default ports used by the Splunk SOAR Connector.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |
