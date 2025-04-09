# ReNgine Utils
[ReNgine](https://github.com/yogeshojha/rengine) CLI tool for interacting with ReNgine API

## Features
- List Vulnerabilities, Subdomains and Endpoints by Domain or Subdomain name
- Generate Reports/Summary in various formats (JSON/CSV/Table)
- Export to visualization/reporting services like Elasticsearch or Faraday
- Scanning Domains for enumeration & vulnerability analysis


### Main
```
usage: rengine-utils.py [-h] {authorize,target,project,scan} ...

options:
  -h, --help            show this help message and exit

options:
  {authorize,target,project,scan}
    authorize
    target
    project
    scan
```
### Authorize
Authorizing is needed to use the tool.
```
usage: rengine-utils.py authorize [-h] [-b --base-url] [-u --user] [-p --password] [-d]

options:
  -h, --help     show this help message and exit
  -b --base-url  URL (ie: https://localhost/)
  -u --user      ReNgine Username
  -p --password  ReNgine Password
  -d             Deletes your session. You should always do this once finished with the tool
```
### Target
```
usage: rengine-utils.py target [-h] {list-subdomains,list-endpoints,list-vulnerabilities,list,generate-summary} ...

options:
  -h, --help            show this help message and exit

target_action:
  {list-subdomains,list-endpoints,list-vulnerabilities,list,generate-summary}
    list-subdomains     List target found subdomains
    list-endpoints      List endpoints by target name or subdomain name
    list-vulnerabilities
                        List endpoints by target name or subdomain name
    list                List targets
    generate-summary    Generates a summary of a domain subdomains and its vulnerabilities
```
### Project
```
usage: rengine-utils.py project [-h] [-l] [-df]

options:
  -h, --help  show this help message and exit
  -l, --list  List the projects
  -df         Returns the default project for the User logged
```

# To do
- General & QOL
    - Error & exception handling
    - Code Refactoring
        - Duplicated Code
        - Spaghetti
        - Better Encapsulation (Improve Reusing)
    - Better Documentation/README (lol)
- Exporting & Reporting
    - Export reports to ElasticSearch ✅
    - Export reports to Faraday ✅
    - Modular Report (Vuln/Subdomains/Urls sections)
- Technologies
    - List Technologies by Target Name
    - List All Technologies
- Tools
    - Add new custom Tools
    - Update existing Tools
- Scan
-   - Running Scans
    - Listing Scans
    - Stop Scans
