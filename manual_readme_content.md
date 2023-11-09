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
## DomainTools Iris Investigate Monitoring Playbook Feature
This feature allows the user to schedule playbooks to run on an specified interval. Coupled with our reference playbooks, linked below, this can be a powerful tool to notify you of domain infrastructure changes, or when newly created domains match specific infrastructure you're monitoring. See the individual playbooks for more information. This readme covers how to set up Iris Monitoring for those playbooks.

### Configuration
This feature depends on the 2 asset configuration fields that are **required** when using this feature.
| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Monitoring Event ID | The numeric ID of a event for the playbook to insert its results. | None | Required |
| Splunk SOAR HTTPS port (default: 8443) | Splunk SOAR HTTP port if your instance uses one other than the default, 8443 | 8443 | Optional |

### Dependencies
This feature uses a custom list named `domaintools_scheduled_playbooks`. <br>
A template was provided alongside the app named `domaintools_scheduled_playbooks.csv` which you can import on your Splunk SOAR instance. <br>
**Note:** The values of this list has 5 columns and the header should not be altered. The last 3 columns are intentionally left blank and used by the playbook scheduler.<br>
**Sample domaintools_scheduled_playbooks table:**
| **repo/playbook_name** | **interval (mins)** | **last_run (server time)** | **last_run_status** | **remarks** |
| --- | --- | --- | --- | --- |
| `local/DomainTools Monitor Domain Risk Score`| 1440 | | | |
| `local/DomainTools Monitor Domain Infrastructure`| 1440 | | | |
| `local/DomainTools Monitor Search Hash`| 1440 | | | |
In this example, we've specified to run three separate monitoring playbooks on daily schedules. Note that each scheduled lookup will consume Iris Investigate queries, depending how many domains or Iris search hashes are being monitored.<br>

### How to use monitoring/scheduling feature in DomainTools Iris Investigate App
1. Under Apps > DomainTools Iris Investigate > Asset Settings > Ingest Settings > **Label**, specify or select a label to apply to objects from this source. **Recommended:** Use a custom label rather using a predefined label like `events`.
2. Specify a polling interval to check if playbooks need to be run. Note that this is separate from the playbook run interval specified in step 4. We recommend running every minute for the most accurate scheduling.
3. Under the Asset Settings tab, specify a **Monitoring Event ID** for the playbook to run into. Optionally change Splunk SOAR HTTP Port if using the non-default 8443. <br>
**Note:** Make sure to label the event you inputted with the label that you selected in *Step 1*.
4. Under Custom Lists > `domaintools_scheduled_playbooks` input your desired playbook schedule following the example in the Configuration Section<br>
**Note:** Make sure the label of the playbook you inputted shares the label that you selected in *Step 1*. The `domaintools_scheduled_playbooks` custom list should have been created when you updated our installed the DomainTools app, but if you don't see it, you can manually create it using the `domaintools_scheduled_playbooks.csv` template bundled with this app.

**Note:** For the DomainTools reference playbooks, see
[this](https://github.com/DomainTools/playbooks/tree/main/Splunk%20SOAR) Github repository.
