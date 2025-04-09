import requests, json, colorama, traceback
from requests import Session
from datetime import datetime
from colorama import Fore, Style

vuln_template = {
    "metadata":{
    "update_time":1533152883.927, 
    "update_user":"", 
    "update_action":0,
    "creator":"UI Web", 
    "create_time":1533152883.927, 
    "update_controller_action":"UI Web New", 
    "owner":"faraday"}, 
    "obj_id":"", 
    "owner":"faraday", 
    "parent":1157, 
    "parent_type":"Host",
    "type":"Vulnerability",
    "ws":"test",
    "confirmed":True,
    "data":"",
    "desc":"New vulnerability created for API purposes",
    "easeofresolution":"simple",
    "impact":{"accountability":False, "availability":False, "confidentiality":False, "integrity":False},
    "name":"New Vuln - Testing API",
    "owned":False,"policyviolations":[],"refs":[], 
    "resolution":"", 
    "severity":"critical", 
    "issuetracker":"", 
    "status":"opened","_attachments":{},
    "description":"",
    "protocol":"",
    "version":""}
service_template = {"name":"Test",
                    "description":"Testing API", 
                    "owned":True, 
                    "owner":"",
                    "ports":[8080],
                    "protocol":"tcp",
                    "parent":1157,
                    "status":"open",
                    "version":"",
                    "metadata":{"update_time":1533152663.994,
                                "update_user":"",
                                "update_action":0,
                                "creator":"",
                                "create_time":1533152663.994,
                                "update_controller_action":"UI Web New","owner":""},
                    "type":"Service"
                    }
asset_template = {"ip":"127.0.0.1",
                  "hostnames":[], 
                  "mac":"00:00:00:00:00:00",
                  "description":"", 
                  "default_gateway":"None", 
                  "os":"Linux", 
                  "owned": False,
                  "owner":""}

cookies = {}
def authenticate(host, user, password):
    data = {'email': f'{user}', 'password': f'{password}'}
    url = host +  "_api/login"
    session = Session()
    try:
        session.post(url, json=data)
    except:
        print("Error authenticating to Faraday Server")
    return session

def list_workspaces(host, session):
    url = host + "_api/v3/ws"
    hosts = session.get(url)
    workspaces = hosts.json()['rows']
    print(workspaces)
    return workspaces

def create_vuln(session, host, workspace, subdomain):
    date = datetime.now()
    url = host + f'_api/v3/ws/{workspace}/vulns'
    headers = {
    'Content-Type': 'application/json',
    }
    if 'vulnerabilities' in subdomain:
        asset_id = create_asset(session, host, workspace, subdomain)
        if asset_id != '':
                print(Fore.YELLOW + "[ℹ️] - " + Style.BRIGHT + f"Uploading Vulnerabilities for: " + Style.NORMAL + f"{subdomain['subdomain_name']}" + Style.RESET_ALL)
                for vuln in subdomain['vulnerabilities']:
                    vuln_f = vuln_template.copy()
                    vuln_f['metadata']['update_time'] = date.timestamp()
                    vuln_f['metadata']['creation_time'] = date.timestamp()
                    vuln_f['metadata']['creator'] = 'rengine-ng'
                    vuln_f['desc'] = vuln['description']
                    vuln_f['severity'] = vuln['severity'].lower()
                    vuln_f['parent'] = asset_id
                    vuln_f['name'] = vuln['name']
                    vuln_f['data'] = vuln['affected_url']
                    vuln_f['creator'] = vuln['source']
                    response = session.post(url, headers=headers, json=vuln_f, verify=False)
                    match response.status_code:
                        case 201:
                            print(Fore.GREEN + Style.BRIGHT + f" [✔] Vulnerability Created for: " + Style.NORMAL + f"{subdomain['subdomain_name']}" + Style.RESET_ALL)
                        case 409:
                            print(Fore.YELLOW + Style.BRIGHT + "[ℹ️] - " + f"Vulnerability Already Created for: " + Style.NORMAL + f"{subdomain['subdomain_name']}" + Style.RESET_ALL)
                        case _:
                            print(Fore.RED + Style.BRIGHT + f"Error uploading vulnerabilities for:" + Style.NORMAL + f"{subdomain['subdomain_name']}" + Style.RESET_ALL)

def create_asset(session, host, workspace, subdomain):
    url = host + f'_api/v3/ws/{workspace}/hosts'
    headers = {
    'Content-Type': 'application/json',
    }
    asset_id = ''
    asset_f = asset_template.copy()
    asset_f['ip'] = subdomain['subdomain_name']
    asset_f['hostnames'] = []
    try:
        for ip in subdomain['ip_addresses']:
            asset_f['hostnames'].append(ip['address'])
        check_os(subdomain, asset_f)            
        response = session.post(url, json=asset_f, verify=False)
        if response.status_code == 201:
            asset_id = response.json()['id']
            print(Fore.GREEN + f" [✔] Asset Created: {subdomain['subdomain_name']}" + Style.RESET_ALL)
        elif response.status_code == 409:
            print(Fore.YELLOW + "[ℹ️] - "  + f"Asset Already Created: " + Style.BRIGHT + f"{subdomain['subdomain_name']}" + Style.RESET_ALL)
            asset_id = response.json()['object']['id']
        else:
            print(Fore.RED + f" [✖] Error Creating Asset: {subdomain['subdomain_name']} in Faraday")
    except Exception as e:
        print(e)
        traceback.print_exc()
    return asset_id

def check_os(subdomain, asset_f):
    linux = ['Red Hat', 'Linux', 'Apache', 'nginx']
    windows = ['IIS']
    techs = []
    os = ''
    if 'urls' in subdomain:
        for url in subdomain['urls']:
            for tech in url['techs']:
                techs.append(tech['name'])
                for l in linux:
                    if tech['name'].startswith(l):
                        os = 'Linux'
                for w in windows:
                    if tech['name'].startswith(w):
                        os = 'Windows'

        asset_f['description'] = "\n".join(techs)
        asset_f['os'] = os
