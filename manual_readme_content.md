[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2023 DomainTools, LLC"
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""

[comment]: # "Monitoring/Scheduling Playbook(s) feature"
## DomainTools Iris Investigate Scheduling/Monitoring  Playbook Feature
This feature allows user to schedule a playbook using a custom list (`domaintools_scheduled_playbooks`) in an interval manner(mins).

### Configuration
This feature depends on the 2 asset configuration field that are **required** when using this feature.
| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Monitoring Container ID | The monitoring container ID that the scheduled playbooks will run into.  | None |Required |
| HTTP Port | Splunk SOAR HTTP port if your instance uses one other than 8443 | 8443 | Optional |

### Dependencies
This feature uses a custom list named `domaintools_scheduled_playbooks`. <br>
A template was provided alongside the app named `domaintools_scheduled_playbooks.csv` which you can import on your splunk SOAR instance. <br>
**Note:** The values of this list has 5 columns header and should not be altered or the scheduling feature will break. <br>
**Sample domaintools_scheduled_playbooks table:**
| **repo/playbook_name** | **interval (mins)** | **last_run (server time)** | **last_run_status** | **remarks** |
| --- | --- | --- | --- | --- |
| `local/My Sample Playbook`| 1440 (default) | | | |

### How to use monitoring/scheduling feature in DomainTools Iris Investigate App
1. In Asset Configuration, go to Asset Settings > Fill up selected Monitoring Container ID > Change Splunk SOAR HTTP Port if needed.
2. Still in Asset Configuration page, go to Ingest Settings > Label to apply to objects from this source >  Select your desired label to use for ingesting. **Recommended:** Use a custom label instead, rather using a predefined label like `events`.
4. Input your desired playbook to schedule in `domaintools_scheduled_playbooks` custom list. <br>
**Note:** Make sure the label of the playbook you inputted should have the label that you selected in *Step 2*.
5. Lastly, in Asset Configuration, go to Ingest Settings > Select a polling interval or schedule to configure polling on this asset > Select `Interval` > Put your desired minutes of interval. **Recommended:** every min (Smaller intervals will result in more accurate schedules)

**Note:** For the playbooks of DomainTools, visit
[this](https://github.com/DomainTools/playbooks/tree/main/Splunk%20SOAR) Github repository.