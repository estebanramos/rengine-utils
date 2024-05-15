# ReNgine Utils
[ReNgine](https://github.com/yogeshojha/rengine) CLI tool based on [rengine-tool](https://github.com/glownd/rengine-tool/) by [@glownd](https://github.com/glownd) (Rollina).

All outputs are in JSON format by default.

## Features
- List Vulnerabilities, Subdomains and Endpoints by Target Name (Domain Name)
- Generate Reports/Summary in JSON format by Target Name

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
- Exporting & Reporting
    - Export reports to ElasticSearch
    - Export reports to Faraday
    - Modular Report (Vuln/Subdomains/Urls sections)
- Technologies
    - List Technologies by Target Name
    - List All Technologies
- Tools
    - Add new custom Tools
    - Update existing Tools
