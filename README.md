[comment]: # "Auto-generated SOAR connector documentation"
# DomainTools Iris Investigate

Publisher: DomainTools  
Connector Version: 1\.4\.0  
Product Vendor: DomainTools  
Product Name: DomainTools Iris Investigate  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.2\.0  

This app supports investigative actions to profile domain names, get risk scores, and find connected domains that share the same Whois details, web hosting profiles, SSL certificates, and more on DomainTools Iris Investigate

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
**Note:** For the playbooks on the domain tools data, visit
[this](https://github.com/DomainTools/playbooks/tree/master/Splunk%20Phantom) Github repository.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a DomainTools Iris Investigate asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**username** |  required  | string | User Name
**key** |  required  | password | API Key
**ssl** |  optional  | boolean | Use SSL

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[domain reputation](#action-domain-reputation) - Evaluates the risk of a given domain  
[pivot action](#action-pivot-action) - Find domains connected by any supported Iris Investigate search parameter  
[reverse domain](#action-reverse-domain) - Extract IPs from a single domain response for further pivoting  
[reverse ip](#action-reverse-ip) - Find domains with web hosting IP, NS IP or MX IP  
[load search hash](#action-load-search-hash) - Load or monitor Iris Investigate search results by Iris Investigate export hash  
[reverse email](#action-reverse-email) - Find domains with email in Whois, DNS SOA or SSL certificate  
[lookup domain](#action-lookup-domain) - Get all Iris Investigate data for a domain using the Iris Investigate API endpoint \(required\)  
[enrich domain](#action-enrich-domain) - Get all Iris Investigate data for a domain except counts using the high volume Iris Enrich API endpoint \(if provisioned\)  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'domain reputation'
Evaluates the risk of a given domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string |  `url`  `domain` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.domain\_risk | numeric | 
action\_result\.summary\.zerolisted | boolean | 
action\_result\.summary\.proximity | numeric | 
action\_result\.summary\.threat\_profile | numeric | 
action\_result\.summary\.threat\_profile\_malware | numeric | 
action\_result\.summary\.threat\_profile\_phishing | numeric | 
action\_result\.summary\.threat\_profile\_spam | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'pivot action'
Find domains connected by any supported Iris Investigate search parameter

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query\_value** |  required  | Value to query | string |  `url`  `domain`  `ip`  `email` 
**pivot\_type** |  required  | Field to pivot on | string | 
**status** |  optional  | Return domains of this registration type | string | 
**data\_updated\_after** |  optional  | Iris Investigate records that were updated on or after midnight on this date, in YYYY\-MM\-DD format or relative options \( 'today', 'yesterday' \) | string | 
**tld** |  optional  | Limit results to only include domains in a specific top\-level domain \(i\.e\. “tld=com” or “tld=ru”\) | string | 
**create\_date** |  optional  | Only include domains created on a specific date, in YYYY\-MM\-DD format or relative options \( 'today', 'yesterday' \) | string | 
**create\_date\_within** |  optional  | Only include domains with a whois create date within the specified number of days \(e\.g\. specifying '1' would indicate within the past day\) | string | 
**first\_seen\_within** |  optional  | Only include domains with a current lifecycle first observed within the specified number of seconds \(e\.g\. specifying '86400' would indicate within the past day\) | string | 
**first\_seen\_since** |  optional  | Only include domains with a current lifecycle first observed since a specified datetime. \(Example: 2023\-04\-10T00:00:00+00:00\) | string | 
**expiration\_date** |  optional  | Only include domains expiring on a specific date, in YYYY\-MM\-DD format or relative options \( 'today', 'yesterday' \) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.create\_date | string | 
action\_result\.parameter\.create\_date\_within | string | 
action\_result\.parameter\.data\_updated\_after | string | 
action\_result\.parameter\.expiration\_date | string | 
action\_result\.parameter\.first\_seen\_since | string | 
action\_result\.parameter\.first\_seen\_within | string | 
action\_result\.parameter\.pivot\_type | string | 
action\_result\.parameter\.query\_value | string |  `url`  `domain`  `ip`  `email` 
action\_result\.parameter\.status | string | 
action\_result\.parameter\.tld | string | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.domain\_risk\.risk\_score | numeric | 
action\_result\.data\.\*\.first\_seen\.count | numeric 
action\_result\.data\.\*\.first\_seen\.value | string 
action\_result\.data\.\*\.server\_type\.count | numeric 
action\_result\.data\.\*\.server\_type\.value | string 
action\_result\.data\.\*\.website\_title\.count | numeric 
action\_result\.data\.\*\.website\_title\.value | string 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'reverse domain'
Extract IPs from a single domain response for further pivoting

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string |  `url`  `domain` 
action\_result\.data | string | 
action\_result\.data\.\*\.first\_seen\.count | numeric 
action\_result\.data\.\*\.first\_seen\.value | string 
action\_result\.data\.\*\.server\_type\.count | numeric 
action\_result\.data\.\*\.server\_type\.value | string 
action\_result\.data\.\*\.website\_title\.count | numeric 
action\_result\.data\.\*\.website\_title\.value | string 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.ip\_list\.\*\.count | numeric | 
action\_result\.summary\.ip\_list\.\*\.ip | string |  `ip` 
action\_result\.summary\.ip\_list\.\*\.type | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'reverse ip'
Find domains with web hosting IP, NS IP or MX IP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address to query | string |  `ip` 
**status** |  optional  | Return domains of this registration type | string | 
**data\_updated\_after** |  optional  | Iris Investigate records that were updated on or after midnight on this date, in YYYY\-MM\-DD format or relative options \( 'today', 'yesterday' \) | string | 
**tld** |  optional  | Limit results to only include domains in a specific top\-level domain \(i\.e\. “tld=com” or “tld=ru”\) | string | 
**create\_date** |  optional  | Only include domains created on a specific date, in YYYY\-MM\-DD format or relative options \( 'today', 'yesterday' \) | string | 
**create\_date\_within** |  optional  | Only include domains with a whois create date within the specified number of days \(e\.g\. specifying '1' would indicate within the past day\) | string | 
**first\_seen\_within** |  optional  | Only include domains with a current lifecycle first observed within the specified number of seconds \(e\.g\. specifying '86400' would indicate within the past day\) | string | 
**first\_seen\_since** |  optional  | Only include domains with a current lifecycle first observed since a specified datetime. \(Example: 2023\-04\-10T00:00:00+00:00\) | string | 
**expiration\_date** |  optional  | Only include domains expiring on a specific date, in YYYY\-MM\-DD format or relative options \( 'today', 'yesterday' \) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.create\_date | string | 
action\_result\.parameter\.create\_date\_within | string | 
action\_result\.parameter\.data\_updated\_after | string | 
action\_result\.parameter\.expiration\_date | string | 
action\_result\.parameter\.first\_seen\_since | string | 
action\_result\.parameter\.first\_seen\_within | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.status | string | 
action\_result\.parameter\.tld | string | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.domain\_risk\.risk\_score | numeric | 
action\_result\.data\.\*\.first\_seen\.count | numeric 
action\_result\.data\.\*\.first\_seen\.value | string 
action\_result\.data\.\*\.server\_type\.count | numeric 
action\_result\.data\.\*\.server\_type\.value | string 
action\_result\.data\.\*\.website\_title\.count | numeric 
action\_result\.data\.\*\.website\_title\.value | string 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'load search hash'
Load or monitor Iris Investigate search results by Iris Investigate export hash

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**search\_hash** |  required  | Iris Investigate search hash to load | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.search\_hash | string | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.domain\_risk\.risk\_score | numeric | 
action\_result\.data\.\*\.first\_seen\.count | numeric 
action\_result\.data\.\*\.first\_seen\.value | string 
action\_result\.data\.\*\.server\_type\.count | numeric 
action\_result\.data\.\*\.server\_type\.value | string 
action\_result\.data\.\*\.website\_title\.count | numeric 
action\_result\.data\.\*\.website\_title\.value | string 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'reverse email'
Find domains with email in Whois, DNS SOA or SSL certificate

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email query | string |  `email` 
**status** |  optional  | Return domains of this registration type | string | 
**data\_updated\_after** |  optional  | Iris Investigate records that were updated on or after midnight on this date, in YYYY\-MM\-DD format or relative options \( 'today', 'yesterday' \) | string | 
**tld** |  optional  | Limit results to only include domains in a specific top\-level domain \(i\.e\. “tld=com” or “tld=ru”\) | string | 
**create\_date** |  optional  | Only include domains created on a specific date, in YYYY\-MM\-DD format or relative options \( 'today', 'yesterday' \) | string | 
**create\_date\_within** |  optional  | Only include domains with a whois create date within the specified number of days \(e\.g\. specifying '1' would indicate within the past day\) | string | 
**first\_seen\_within** |  optional  | Only include domains with a current lifecycle first observed within the specified number of seconds \(e\.g\. specifying '86400' would indicate within the past day\) | string | 
**first\_seen\_since** |  optional  | Only include domains with a current lifecycle first observed since a specified datetime. \(Example: 2023\-04\-10T00:00:00+00:00\) | string | 
**expiration\_date** |  optional  | Only include domains expiring on a specific date, in YYYY\-MM\-DD format or relative options \( 'today', 'yesterday' \) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.create\_date | string | 
action\_result\.parameter\.create\_date\_within | string | 
action\_result\.parameter\.data\_updated\_after | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.parameter\.expiration\_date | string | 
action\_result\.parameter\.first\_seen\_since | string | 
action\_result\.parameter\.first\_seen\_within | string | 
action\_result\.parameter\.status | string | 
action\_result\.parameter\.tld | string | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.domain\_risk\.risk\_score | numeric | 
action\_result\.data\.\*\.first\_seen\.count | numeric 
action\_result\.data\.\*\.first\_seen\.value | string 
action\_result\.data\.\*\.server\_type\.count | numeric 
action\_result\.data\.\*\.server\_type\.value | string 
action\_result\.data\.\*\.website\_title\.count | numeric 
action\_result\.data\.\*\.website\_title\.value | string 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup domain'
Get all Iris Investigate data for a domain using the Iris Investigate API endpoint \(required\)

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query using the Iris Investigate API | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `url`  `domain` 
action\_result\.data\.\*\.additional\_whois\_email\.\*\.count | numeric | 
action\_result\.data\.\*\.additional\_whois\_email\.\*\.value | string | 
action\_result\.data\.\*\.admin\_contact\.city\.count | numeric | 
action\_result\.data\.\*\.admin\_contact\.city\.value | string | 
action\_result\.data\.\*\.admin\_contact\.country\.count | numeric | 
action\_result\.data\.\*\.admin\_contact\.country\.value | string | 
action\_result\.data\.\*\.admin\_contact\.fax\.count | numeric | 
action\_result\.data\.\*\.admin\_contact\.fax\.value | string | 
action\_result\.data\.\*\.admin\_contact\.name\.count | numeric | 
action\_result\.data\.\*\.admin\_contact\.name\.value | string | 
action\_result\.data\.\*\.admin\_contact\.org\.count | numeric | 
action\_result\.data\.\*\.admin\_contact\.org\.value | string | 
action\_result\.data\.\*\.admin\_contact\.phone\.count | numeric | 
action\_result\.data\.\*\.admin\_contact\.phone\.value | string | 
action\_result\.data\.\*\.admin\_contact\.postal\.count | numeric | 
action\_result\.data\.\*\.admin\_contact\.postal\.value | string | 
action\_result\.data\.\*\.admin\_contact\.state\.count | numeric | 
action\_result\.data\.\*\.admin\_contact\.state\.value | string | 
action\_result\.data\.\*\.admin\_contact\.street\.count | numeric | 
action\_result\.data\.\*\.admin\_contact\.street\.value | string | 
action\_result\.data\.\*\.adsense\.count | numeric | 
action\_result\.data\.\*\.adsense\.value | string | 
action\_result\.data\.\*\.alexa | numeric | 
action\_result\.data\.\*\.billing\_contact\.city\.count | numeric | 
action\_result\.data\.\*\.billing\_contact\.city\.value | string | 
action\_result\.data\.\*\.billing\_contact\.country\.count | numeric | 
action\_result\.data\.\*\.billing\_contact\.country\.value | string | 
action\_result\.data\.\*\.billing\_contact\.fax\.count | numeric | 
action\_result\.data\.\*\.billing\_contact\.fax\.value | string | 
action\_result\.data\.\*\.billing\_contact\.name\.count | numeric | 
action\_result\.data\.\*\.billing\_contact\.name\.value | string | 
action\_result\.data\.\*\.billing\_contact\.org\.count | numeric | 
action\_result\.data\.\*\.billing\_contact\.org\.value | string | 
action\_result\.data\.\*\.billing\_contact\.phone\.count | numeric | 
action\_result\.data\.\*\.billing\_contact\.phone\.value | string | 
action\_result\.data\.\*\.billing\_contact\.postal\.count | numeric | 
action\_result\.data\.\*\.billing\_contact\.postal\.value | string | 
action\_result\.data\.\*\.billing\_contact\.state\.count | numeric | 
action\_result\.data\.\*\.billing\_contact\.state\.value | string | 
action\_result\.data\.\*\.billing\_contact\.street\.count | numeric | 
action\_result\.data\.\*\.billing\_contact\.street\.value | string | 
action\_result\.data\.\*\.create\_date\.count | numeric | 
action\_result\.data\.\*\.create\_date\.value | string | 
action\_result\.data\.\*\.email\_domain\.\*\.count | numeric | 
action\_result\.data\.\*\.email\_domain\.\*\.value | string | 
action\_result\.data\.\*\.expiration\_date\.count | numeric | 
action\_result\.data\.\*\.expiration\_date\.value | string | 
action\_result\.data\.\*\.first\_seen\.count | numeric 
action\_result\.data\.\*\.first\_seen\.value | string 
action\_result\.data\.\*\.google\_analytics\.count | numeric | 
action\_result\.data\.\*\.google\_analytics\.value | string | 
action\_result\.data\.\*\.ip\.\*\.address\.count | numeric | 
action\_result\.data\.\*\.ip\.\*\.address\.value | string | 
action\_result\.data\.\*\.ip\.\*\.asn\.\*\.count | numeric | 
action\_result\.data\.\*\.ip\.\*\.asn\.\*\.value | string | 
action\_result\.data\.\*\.ip\.\*\.country\_code\.count | numeric | 
action\_result\.data\.\*\.ip\.\*\.country\_code\.value | string | 
action\_result\.data\.\*\.ip\.\*\.isp\.count | numeric | 
action\_result\.data\.\*\.ip\.\*\.isp\.value | string | 
action\_result\.data\.\*\.mx\.\*\.domain\.count | numeric | 
action\_result\.data\.\*\.mx\.\*\.domain\.value | string | 
action\_result\.data\.\*\.mx\.\*\.host\.count | numeric | 
action\_result\.data\.\*\.mx\.\*\.host\.value | string | 
action\_result\.data\.\*\.mx\.\*\.ip\.\*\.count | numeric | 
action\_result\.data\.\*\.mx\.\*\.ip\.\*\.value | string | 
action\_result\.data\.\*\.name\_server\.\*\.domain\.count | numeric | 
action\_result\.data\.\*\.name\_server\.\*\.domain\.value | string | 
action\_result\.data\.\*\.name\_server\.\*\.host\.count | numeric | 
action\_result\.data\.\*\.name\_server\.\*\.host\.value | string | 
action\_result\.data\.\*\.name\_server\.\*\.ip\.\*\.count | numeric | 
action\_result\.data\.\*\.name\_server\.\*\.ip\.\*\.value | string | 
action\_result\.data\.\*\.redirect\.count | numeric | 
action\_result\.data\.\*\.redirect\.value | string | 
action\_result\.data\.\*\.redirect\_domain\.count | numeric | 
action\_result\.data\.\*\.redirect\_domain\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.city\.count | numeric | 
action\_result\.data\.\*\.registrant\_contact\.city\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.country\.count | numeric | 
action\_result\.data\.\*\.registrant\_contact\.country\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.email\.\*\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.fax\.count | numeric | 
action\_result\.data\.\*\.registrant\_contact\.fax\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.name\.count | numeric | 
action\_result\.data\.\*\.registrant\_contact\.name\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.org\.count | numeric | 
action\_result\.data\.\*\.registrant\_contact\.org\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.phone\.count | numeric | 
action\_result\.data\.\*\.registrant\_contact\.phone\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.postal\.count | numeric | 
action\_result\.data\.\*\.registrant\_contact\.postal\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.state\.count | numeric | 
action\_result\.data\.\*\.registrant\_contact\.state\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.street\.count | numeric | 
action\_result\.data\.\*\.registrant\_contact\.street\.value | string | 
action\_result\.data\.\*\.registrant\_name\.count | numeric | 
action\_result\.data\.\*\.registrant\_name\.value | string | 
action\_result\.data\.\*\.registrant\_org\.count | numeric | 
action\_result\.data\.\*\.registrant\_org\.value | string | 
action\_result\.data\.\*\.registrar\.count | numeric | 
action\_result\.data\.\*\.registrar\.value | string | 
action\_result\.data\.\*\.server\_type\.count | numeric 
action\_result\.data\.\*\.server\_type\.value | string 
action\_result\.data\.\*\.soa\_email\.\*\.count | numeric | 
action\_result\.data\.\*\.soa\_email\.\*\.value | string | 
action\_result\.data\.\*\.ssl\_info\.\*\.hash\.count | numeric | 
action\_result\.data\.\*\.ssl\_info\.\*\.hash\.value | string | 
action\_result\.data\.\*\.ssl\_info\.\*\.organization\.count | numeric | 
action\_result\.data\.\*\.ssl\_info\.\*\.organization\.value | string | 
action\_result\.data\.\*\.ssl\_info\.\*\.subject\.count | numeric | 
action\_result\.data\.\*\.ssl\_info\.\*\.subject\.value | string | 
action\_result\.data\.\*\.tags\.\*\.label | string | 
action\_result\.data\.\*\.technical\_contact\.city\.count | numeric | 
action\_result\.data\.\*\.technical\_contact\.city\.value | string | 
action\_result\.data\.\*\.technical\_contact\.country\.count | numeric | 
action\_result\.data\.\*\.technical\_contact\.country\.value | string | 
action\_result\.data\.\*\.technical\_contact\.fax\.count | numeric | 
action\_result\.data\.\*\.technical\_contact\.fax\.value | string | 
action\_result\.data\.\*\.technical\_contact\.name\.count | numeric | 
action\_result\.data\.\*\.technical\_contact\.name\.value | string | 
action\_result\.data\.\*\.technical\_contact\.org\.count | numeric | 
action\_result\.data\.\*\.technical\_contact\.org\.value | string | 
action\_result\.data\.\*\.technical\_contact\.phone\.count | numeric | 
action\_result\.data\.\*\.technical\_contact\.phone\.value | string | 
action\_result\.data\.\*\.technical\_contact\.postal\.count | numeric | 
action\_result\.data\.\*\.technical\_contact\.postal\.value | string | 
action\_result\.data\.\*\.technical\_contact\.state\.count | numeric | 
action\_result\.data\.\*\.technical\_contact\.state\.value | string | 
action\_result\.data\.\*\.technical\_contact\.street\.count | numeric | 
action\_result\.data\.\*\.technical\_contact\.street\.value | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'enrich domain'
Get all Iris Investigate data for a domain except counts using the high volume Iris Enrich API endpoint \(if provisioned\)

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query using the Iris Enrich API \(if provisioned\) | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `url`  `domain` 
action\_result\.data\.\*\.additional\_whois\_email\.\*\.value | string | 
action\_result\.data\.\*\.admin\_contact\.city\.value | string | 
action\_result\.data\.\*\.admin\_contact\.country\.value | string | 
action\_result\.data\.\*\.admin\_contact\.fax\.value | string | 
action\_result\.data\.\*\.admin\_contact\.name\.value | string | 
action\_result\.data\.\*\.admin\_contact\.org\.value | string | 
action\_result\.data\.\*\.admin\_contact\.phone\.value | string | 
action\_result\.data\.\*\.admin\_contact\.postal\.value | string | 
action\_result\.data\.\*\.admin\_contact\.state\.value | string | 
action\_result\.data\.\*\.admin\_contact\.street\.value | string | 
action\_result\.data\.\*\.adsense\.value | string | 
action\_result\.data\.\*\.alexa | numeric | 
action\_result\.data\.\*\.billing\_contact\.city\.value | string | 
action\_result\.data\.\*\.billing\_contact\.country\.value | string | 
action\_result\.data\.\*\.billing\_contact\.fax\.value | string | 
action\_result\.data\.\*\.billing\_contact\.name\.value | string | 
action\_result\.data\.\*\.billing\_contact\.org\.value | string | 
action\_result\.data\.\*\.billing\_contact\.phone\.value | string | 
action\_result\.data\.\*\.billing\_contact\.postal\.value | string | 
action\_result\.data\.\*\.billing\_contact\.state\.value | string | 
action\_result\.data\.\*\.billing\_contact\.street\.value | string | 
action\_result\.data\.\*\.create\_date\.value | string | 
action\_result\.data\.\*\.email\_domain\.\*\.value | string | 
action\_result\.data\.\*\.expiration\_date\.value | string | 
action\_result\.data\.\*\.first\_seen\.value | string 
action\_result\.data\.\*\.google\_analytics\.value | string | 
action\_result\.data\.\*\.ip\.\*\.address\.value | string | 
action\_result\.data\.\*\.ip\.\*\.asn\.\*\.value | string | 
action\_result\.data\.\*\.ip\.\*\.country\_code\.value | string | 
action\_result\.data\.\*\.ip\.\*\.isp\.value | string | 
action\_result\.data\.\*\.mx\.\*\.domain\.value | string | 
action\_result\.data\.\*\.mx\.\*\.host\.value | string | 
action\_result\.data\.\*\.mx\.\*\.ip\.\*\.value | string | 
action\_result\.data\.\*\.name\_server\.\*\.domain\.value | string | 
action\_result\.data\.\*\.name\_server\.\*\.host\.value | string | 
action\_result\.data\.\*\.name\_server\.\*\.ip\.\*\.value | string | 
action\_result\.data\.\*\.redirect\.value | string | 
action\_result\.data\.\*\.redirect\_domain\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.city\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.country\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.email\.\*\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.fax\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.name\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.org\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.phone\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.postal\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.state\.value | string | 
action\_result\.data\.\*\.registrant\_contact\.street\.value | string | 
action\_result\.data\.\*\.registrant\_name\.value | string | 
action\_result\.data\.\*\.registrant\_org\.value | string | 
action\_result\.data\.\*\.registrar\.value | string | 
action\_result\.data\.\*\.server\_type\.value | string 
action\_result\.data\.\*\.soa\_email\.\*\.value | string | 
action\_result\.data\.\*\.ssl\_info\.\*\.hash\.value | string | 
action\_result\.data\.\*\.ssl\_info\.\*\.organization\.value | string | 
action\_result\.data\.\*\.ssl\_info\.\*\.subject\.value | string | 
action\_result\.data\.\*\.tags\.\*\.label | string | 
action\_result\.data\.\*\.technical\_contact\.city\.value | string | 
action\_result\.data\.\*\.technical\_contact\.country\.value | string | 
action\_result\.data\.\*\.technical\_contact\.fax\.value | string | 
action\_result\.data\.\*\.technical\_contact\.name\.value | string | 
action\_result\.data\.\*\.technical\_contact\.org\.value | string | 
action\_result\.data\.\*\.technical\_contact\.phone\.value | string | 
action\_result\.data\.\*\.technical\_contact\.postal\.value | string | 
action\_result\.data\.\*\.technical\_contact\.state\.value | string | 
action\_result\.data\.\*\.technical\_contact\.street\.value | string | 
action\_result\.data\.\*\.website\_title\.value | string 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 