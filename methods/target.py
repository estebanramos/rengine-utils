import methods.utils as utils
import pyperclip, os, re, socket, requests, colorama, traceback, signal
from rich.console import Console
from rich.table import Table
from rich.text import Text
from colorama import Fore, Style
from pwn import *
from termcolor import colored


def def_handler(sig, frame):
    print("Exiting...")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def output_file_json(filename, subdomain_list):
    final_filename = utils.normalize_filename(filename, 'json')
    f = open(final_filename, 'w+')
    try:
        for item in subdomain_list:
            f.write(utils.prettyPrintJSON(item))
    except:
        pass
    if os.path.isfile(final_filename): print(f"Report has been copied to {final_filename}")
    

def generateSummaryByTargetName(name, s, project_name, clip, output, show, vulns_filter):
    console = Console()
    console.print(Text(f'Generating report for: {name}', style='bold yellow'))
    # target_id = findTargetIdByName(name, s)['target_id']
    subdomain_summary = getSubdomainsByTargetName(name, s, project_name)
    subdomain_list = subdomain_summary['subdomains']
    vulnerabilities_list = getVulnerabilitiesByTargetName(name, s, vulns_filter)
    urls_list = getEndpointsByTargetName(name, s, project_name)
    for item in subdomain_list:
        for item2 in vulnerabilities_list:
            if item['subdomain']['subdomain_name'] == item2['subdomain']['name']:
                item['subdomain']['vulnerabilities'] = item2['subdomain']['vulnerabilities']
        for item3 in urls_list:
            if 'urls' in item3.keys() and (
                    item['subdomain']['subdomain_name'] == item3['subdomain_name']):
                item['subdomain']['urls'] = item3['urls']

    for item in subdomain_list:
        if show:
            utils.cleanUselessStuffFromDict(item['subdomain'], ['id'])
            print(utils.prettyPrintJSON(item))

    if output: output_file_json(output, subdomain_list)

    if clip:
        try:
            pyperclip.copy(str(subdomain_list))
            print("The report has been copied to your clipboard!")
        except Exception as e:
            print("Error copying the report to your clipboard")
            print(e)
    return subdomain_list


def generateGeneralSummary(s, project_name, export=None, vulns_filter=None, output="general-report.json"):
    p1 = log.progress("Report")
    console = Console()
    #console.print(Text('Generating report, this should take a while...grab a coffee', style='bold yellow'))
    if export:
        console.print(Text('...and also you are exporting, you better go touch some grass', style='bold green'))
    target_list = getTargets(s)
    general_summary = []
    for target in target_list:
        try:
            p1.status(f"Now processing {target['name']}")
            #print(Fore.YELLOW + Style.BRIGHT + "[ℹ️] " + f"Now Processing: " + Style.NORMAL + f"{target['name']}" + Style.RESET_ALL)
            subdomain_summary = getSubdomainsByTargetName(target['name'], s, project_name)
            if 'subdomains' not in subdomain_summary:
                print(Fore.GREEN + Style.BRIGHT + f" [✓] Finished Processing: " + Style.NORMAL + f"{target['name']}" + Style.RESET_ALL)
                continue
            subdomain_list = subdomain_summary['subdomains']
            vulnerabilities_list = getVulnerabilitiesByTargetName(target['name'], s, vulns_filter)
            urls_list = getEndpointsByTargetName(target['name'], s, project_name)
            for item in subdomain_list:
                for item2 in vulnerabilities_list:
                    if item['subdomain']['subdomain_name'] == item2['subdomain']['name']:
                        item['subdomain']['vulnerabilities'] = item2['subdomain']['vulnerabilities']
                for item3 in urls_list:
                    if 'urls' in item3.keys() and (
                            item['subdomain']['subdomain_name'] == item3['subdomain_name']):
                        item['subdomain']['urls'] = item3['urls']
            p1.status(f"Finished processing: {target['name']}")
            print(Fore.GREEN + Style.BRIGHT + f" [✓] Finished Processing: " + Style.NORMAL + f"{target['name']}" + Style.RESET_ALL)
            general_summary.append(subdomain_list)
        except Exception as e:
            if isinstance(e, SystemExit):
                raise
            else:
                print(f"Error processing: {target['name']}")
                traceback.print_exc()
    console.print(Text('Finished generating report', style='bold yellow'))
    if output: output_file_json("general-report.json", general_summary)
    return general_summary


def listVulnerabilitiesByTargetName(name, s):
    target_id = findTargetIdByName(name, s)['target_id']
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + \
        f'/api/listVulnerability/?target_id={target_id}&format=datatables&search[value]=severity=Medium | severity=High | severity=Critical | severity=Low'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()
    root = {"domain": name, "subdomains": []}
    temporal = {}
    for item in j['data']:
        if item['subdomain']:
            subdomain = item['subdomain']['name']
        else:
            subdomain = item['http_url'].strip('https://').split('/')[0]
        vulnerability_name = item['name']
        affected_url = item['http_url']
        severity = item['severity']
        source = item['source']
        if subdomain not in temporal.keys():
            i = {"subdomain": {
                "name": subdomain,
                "vulnerabilities": [
                    {
                        "name": vulnerability_name,
                        "severity": severity,
                        "affected_url": affected_url,
                        "source": source
                    }
                ]
            }
            }
            temporal.update({subdomain: i})
            root['subdomains'].append(i)
        else:
            vuln = {"name": vulnerability_name,
                    "severity": severity,
                    "affected_url": affected_url,
                    "source": source
                    }
            temporal[subdomain]['subdomain']['vulnerabilities'].append(vuln)
    for item in root['subdomains']:
        print(utils.prettyPrintJSON(item))

def getVulnerabilitiesByTargetName(name, s, filter=None):
    if filter is not None:
        filter_param = "search[value]="
        for f in filter:
            filter_param += f"severity={f.capitalize()} | "
    else:
        filter_param = "search[value]=severity=Medium | severity=High | severity=Critical | severity=Low"
    target_id = findTargetIdByName(name, s)['target_id']
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + \
        f'/api/listVulnerability/?target_id={target_id}&format=datatables&{filter_param}'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()
    root = {"domain": name, "subdomains": []}
    temporal = {}
    for item in j['data']:
        if item['subdomain']:
            subdomain = item['subdomain']['name']
        else:
            subdomain = item['http_url'].strip('https://').split('/')[0]
        vulnerability_name = item['name']
        affected_url = item['http_url']
        severity = item['severity']
        source = item['source']
        description = item['description']
        tags = item['tags']
        if subdomain not in temporal.keys():
            i = {"subdomain": {
                "name": subdomain,
                "vulnerabilities": [
                    {
                        "name": vulnerability_name,
                        "severity": severity,
                        "affected_url": affected_url,
                        "source": source,
                        "description": description,
                        "tags": tags
                    }
                ]
            }
            }
            temporal.update({subdomain: i})
            root['subdomains'].append(i)
        else:
            vuln = {"name": vulnerability_name,
                    "severity": severity,
                    "affected_url": affected_url,
                    "source": source,
                    "description": description,
                    "tags": tags
                    }
            temporal[subdomain]['subdomain']['vulnerabilities'].append(vuln)
    return root['subdomains']

def listEndpointsByTargetName(name, s, project_name):
    try:
        target_id = findTargetIdByName(name, s)['target_id']
    except BaseException:
        print(f"The target {name} doesn't exists in reNgine's project {project_name}")
        return
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + \
        f'/api/listEndpoints/?format=datatables&project={project_name}&target_id={target_id}'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()['data']
    mapped = mapUrlsToSubdomains(name, j, s, project_name)
    for item in mapped:
        print(utils.prettyPrintJSON(mapped))

def getEndpointsByTargetName(name, s, project_name):
    target_id = findTargetIdByName(name, s)['target_id']
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + \
        f'/api/listEndpoints/?format=datatables&project={project_name}&target_id={target_id}'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()['data']
    mapped = mapUrlsToSubdomains(name, j, s, project_name)
    return mapped


def listEndpointsBySubdomainName(name, s, project_name):
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + f'/api/listEndpoints/?format=datatables&project={project_name}&draw=2&columns[0][data]=id&columns[0][name]=&columns[0][searchable]=false&columns[0][orderable]=true&columns[0][search][value]=&columns[0][search][regex]=false&columns[1][data]=http_url&columns[1][name]=&columns[1][searchable]=true&columns[1][orderable]=true&columns[1][search][value]=&columns[1][search][regex]=false&columns[2][data]=http_status&columns[2][name]=&columns[2][searchable]=true&columns[2][orderable]=true&columns[2][search][value]=&columns[2][search][regex]=false&columns[3][data]=page_title&columns[3][name]=&columns[3][searchable]=true&columns[3][orderable]=true&columns[3][search][value]=&columns[3][search][regex]=false&columns[4][data]=matched_gf_patterns&columns[4][name]=&columns[4][searchable]=true&columns[4][orderable]=true&columns[4][search][value]=&columns[4][search][regex]=false&columns[5][data]=content_type&columns[5][name]=&columns[5][searchable]=true&columns[5][orderable]=true&columns[5][search][value]=&columns[5][search][regex]=false&columns[6][data]=content_length&columns[6][name]=&columns[6][searchable]=false&columns[6][orderable]=true&columns[6][search][value]=&columns[6][search][regex]=false&columns[7][data]=techs&columns[7][name]=&columns[7][searchable]=true&columns[7][orderable]=true&columns[7][search][value]=&columns[7][search][regex]=false&columns[8][data]=webserver&columns[8][name]=&columns[8][searchable]=true&columns[8][orderable]=true&columns[8][search][value]=&columns[8][search][regex]=false&columns[9][data]=response_time&columns[9][name]=&columns[9][searchable]=false&columns[9][orderable]=true&columns[9][search][value]=&columns[9][search][regex]=false&order[0][column]=6&order[0][dir]=desc&start=0&search[value]=&search[regex]=false&_=1710782920706'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()['data']
    root = {"subdomain": {
        "subdomain_name": name,
        "urls": []
    }
    }
    urls = []
    for item in j:
        if name == item['http_url'].strip('https://').split('/')[0]:
            i = {
                "http_url": item['http_url'],
                "title": item['page_title'],
                "webserver": item['webserver'],
                "techs": item["techs"]
            }
            root['subdomain']['urls'].append(i)
    print(type(root))
    print(utils.prettyPrintJSON(root))


def listSubdomainsByTargetNameJSON(name, s, project):
    if TargetExists(name, s):
        target_id = findTargetIdByName(name, s)['target_id']
    else:
        print("Target doesn't exists!")
        return {}
    target_id = findTargetIdByName(name, s)['target_id']
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + \
        f'/api/listDatatableSubdomain/?project={project.lower()}&target_id={target_id}&format=datatables&length=0'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()
    root = {"domain": name, "subdomains": []}
    temporal = []
    if not len(j['data']):
        print(f" {name} Target exists but doesn't have subdomains associated. Be sure to scan it for subdomains or ensure that you are selecting the correct project")
        return {}
    for item in j['data']:
        subdomain = item['name']
        http_status = item['http_status']
        if item['name'] not in temporal:
            ip_addresses = []
            if item['ip_addresses']:
                for item2 in item['ip_addresses']:
                    ports = []
                    port_info = {
                    }
                    for port in item2['ports']:
                        port_info = {"number": port['number'],
                                     "service": port['service_name']
                                     }
                        ports.append(port_info)
                    ip_address = {
                        "address": item2['address'],
                        "ports": port_info}
                    ip_addresses.append(ip_address)

            i = {"subdomain": {
                "domain": name,
                "subdomain_name": subdomain,
                "ip_addresses": ip_addresses,
                "id": item['id'],
                "http_status": http_status

            }
            }
            root['subdomains'].append(i)
            temporal.append(item['name'])
    for item in root['subdomains']:
        utils.cleanUselessStuffFromDict(item['subdomain'], ['id'])
        print(utils.prettyPrintJSON(item) + ',')
    pyperclip.copy(str(root['subdomains']))


def listSubdomainsByTargetNameTable(name, s, project):
    if TargetExists(name, s):
        target_id = findTargetIdByName(name, s)['target_id']
    else:
        print("Target doesn't exists!")
        return {}
    target_id = findTargetIdByName(name, s)['target_id']
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + \
        f'/api/listDatatableSubdomain/?project={project.lower()}&target_id={target_id}&format=datatables&length=0'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()
    if not len(j['data']):
        print("Target exists but doesn't have subdomains associated. Be sure to scan it for subdomains")
        return {}
    root = j['data']
    table = Table(title=f'Subdomains for {name}')
    columns = ["Subdomain", "HTTP Status", "Page Title", "IPs Addresses", "Ports", "ID"]
    for column in columns:
        table.add_column(column)
    for item in root:
        ipv4_addresses = [ip['address']
                          for ip in item['ip_addresses'] if '.' in ip['address']]
        try:
            if len(ipv4_addresses) == 0:
                resolved_ips = socket.gethostbyname_ex(item['name'])
                ipv4_addresses = resolved_ips[2]
                ipv4_addresses_str = ', '.join(ipv4_addresses)
            else:
                ipv4_addresses_str = ', '.join(ipv4_addresses)
        except BaseException:
            ipv4_addresses_str = ''
        if item['http_status'] == 0:
            item['http_status'] = ''
        http_status_str = str(item['http_status'])
        http_status_style = 'green' if http_status_str == '200' else 'red'
        port_numbers = []
        for ip_info in item['ip_addresses']:
            if 'ports' in ip_info:
                for port in ip_info['ports']:
                    port_numbers.append(port['number'])
        unique_ports = " ".join(map(str, set(port_numbers)))
        row = [item['name'],
               f"[{http_status_style}]{http_status_str}[/{http_status_style}]",
               item['page_title'],
               ipv4_addresses_str,
               unique_ports,
               str(item['id'])]
        table.add_row(*row)
    console = Console()
    console.print(table)

def getSubdomainsByTargetName(name, s, project):
    if TargetExists(name, s):
        target_id = findTargetIdByName(name, s)['target_id']
    else:
        print("Target doesn't exists!")
        return {}
    target_id = findTargetIdByName(name, s)['target_id']
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + \
        f'/api/listDatatableSubdomain/?project={project}&target_id={target_id}&format=datatables&&format=datatables&draw=1'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    try:
        j = r.json()
    except:
        print("Failed to process json", r)
        return 
    root = {"domain": name, "subdomains": []}
    temporal = []
    if not len(j['data']):
        print(colored(f" [!] {name} domain exists but doesn't have any subdomains associated. Be sure to scan it for subdomains",'yellow', attrs=['bold']))
        return {}
    subdomain_list = removeDuplicatedSubdomains(j['data'])
    for item in subdomain_list:
        subdomain = item['name']
        http_status = item['http_status']
        if 'page_title' in item: page_title = item['page_title']
        else: page_title = ""
        if item['name'] not in temporal:
            ip_addresses = []
            if item['ip_addresses']:
                for item2 in item['ip_addresses']:
                    ports = []
                    port_info = {
                    }
                    for port in item2['ports']:
                        port_info = {"number": port['number'],
                                     "service": port['service_name']
                                     }
                        ports.append(port_info)
                    ip_address = {
                        "address": item2['address'],
                        "ports": item2['ports']}
                    ip_addresses.append(ip_address)
            if item['discovered_date']:
                discovered_date = item['discovered_date']

            i = {"subdomain": {
                "domain": name,
                "subdomain_name": subdomain,
                "ip_addresses": ip_addresses,
                "id": item['id'],
                "http_status": http_status,
                "page_title": page_title,
                "discovered_date": discovered_date

            }
            }
            root['subdomains'].append(i)
            temporal.append(item['name'])
    return root


def findTargetIdByName(name, s):

    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + '/api/listTargets/?format=datatables'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()['data']
    for item in j:
        if item['name'] == name:
            i = {'name': name,
                 'target_id': item['id']
                 }
            return i


def listTargets(s):
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + '/api/listTargets/?format=datatables'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()['data']
    for item in j:
        print(utils.prettyPrintJSON(item))
    print("\nIf you want a more clean output try using --clean")
    return j

def getTargets(s):
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + '/api/listTargets/?format=datatables'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()['data']
    return j


def listTargetsTable(s):
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + '/api/listTargets/?format=datatables'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()['data']
    table = Table(title='Targets')
    columns = ['Name', 'Last Scan', 'Project/Slug', 'ID']
    for column in columns:
        table.add_column(column)
    for item in j:
        row = [item['name'], item['start_scan_date_humanized'],
               item['project']['name'], str(item['id'])]
        table.add_row(*row, style='bright_green')
    console = Console()
    console.print(table)


def listCleanTargets(s):
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + '/api/listTargets/?format=datatables'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()['data']
    for item in j:
        i = {
            "id": item['id'],
            "target": item['name']
        }
        print(utils.prettyPrintJSON(i))
    return j


def TargetExists(name, s):
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + '/api/listTargets/?format=datatables'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()['data']
    for item in j:
        if item['name'] == name:
            return True
    return False


def mapUrlsToSubdomains(name, dict, s, project):
    subdomains = getSubdomainsByTargetName(name, s, project)
    subdomains_with_urls = []
    for item in subdomains['subdomains']:
        for item2 in dict:
            if item2['http_url'].strip(
                    'https://').split('/')[0] == item['subdomain']['subdomain_name']:
                i = {
                    "http_url": item2['http_url'],
                    "title": item2['page_title'],
                    "webserver": item2['webserver'],
                    "techs": item2["techs"]
                }
                if subdomainExistsInDict(
                        subdomains_with_urls, item['subdomain']['subdomain_name']):
                    item['subdomain']['urls'].append(i)
                else:
                    item['subdomain']['urls'] = []
                    item['subdomain']['urls'].append(i)
                    subdomains_with_urls.append(item['subdomain'])
    return subdomains_with_urls


def subdomainExistsInDict(dict, subdomain):
    for item in dict:
        if item['subdomain_name'] == subdomain:
            return True
    return False


def listVulnerabilitiesBySubdomain(subdomain_name, s, project_name):
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + f'/api/listVulnerability/?project={project_name}&format=datatables&draw=3&columns%5B0%5D%5Bdata%5D=id&columns%5B0%5D%5Bname%5D=&columns%5B0%5D%5Bsearchable%5D=true&columns%5B0%5D%5Borderable%5D=true&columns%5B0%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B0%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B1%5D%5Bdata%5D=source&columns%5B1%5D%5Bname%5D=&columns%5B1%5D%5Bsearchable%5D=true&columns%5B1%5D%5Borderable%5D=true&columns%5B1%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B1%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B2%5D%5Bdata%5D=type&columns%5B2%5D%5Bname%5D=&columns%5B2%5D%5Bsearchable%5D=true&columns%5B2%5D%5Borderable%5D=true&columns%5B2%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B2%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B3%5D%5Bdata%5D=name&columns%5B3%5D%5Bname%5D=&columns%5B3%5D%5Bsearchable%5D=true&columns%5B3%5D%5Borderable%5D=true&columns%5B3%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B3%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B4%5D%5Bdata%5D=cvss_metrics&columns%5B4%5D%5Bname%5D=&columns%5B4%5D%5Bsearchable%5D=true&columns%5B4%5D%5Borderable%5D=true&columns%5B4%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B4%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B5%5D%5Bdata%5D=tags&columns%5B5%5D%5Bname%5D=&columns%5B5%5D%5Bsearchable%5D=true&columns%5B5%5D%5Borderable%5D=true&columns%5B5%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B5%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B6%5D%5Bdata%5D=hackerone_report_id&columns%5B6%5D%5Bname%5D=&columns%5B6%5D%5Bsearchable%5D=true&columns%5B6%5D%5Borderable%5D=true&columns%5B6%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B6%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B7%5D%5Bdata%5D=severity&columns%5B7%5D%5Bname%5D=&columns%5B7%5D%5Bsearchable%5D=true&columns%5B7%5D%5Borderable%5D=true&columns%5B7%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B7%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B8%5D%5Bdata%5D=cvss_score&columns%5B8%5D%5Bname%5D=&columns%5B8%5D%5Bsearchable%5D=true&columns%5B8%5D%5Borderable%5D=true&columns%5B8%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B8%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B9%5D%5Bdata%5D=cve_ids&columns%5B9%5D%5Bname%5D=&columns%5B9%5D%5Bsearchable%5D=true&columns%5B9%5D%5Borderable%5D=true&columns%5B9%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B9%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B10%5D%5Bdata%5D=cwe_ids&columns%5B10%5D%5Bname%5D=&columns%5B10%5D%5Bsearchable%5D=true&columns%5B10%5D%5Borderable%5D=true&columns%5B10%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B10%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B11%5D%5Bdata%5D=http_url&columns%5B11%5D%5Bname%5D=&columns%5B11%5D%5Bsearchable%5D=true&columns%5B11%5D%5Borderable%5D=true&columns%5B11%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B11%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B12%5D%5Bdata%5D=description&columns%5B12%5D%5Bname%5D=&columns%5B12%5D%5Bsearchable%5D=true&columns%5B12%5D%5Borderable%5D=true&columns%5B12%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B12%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B13%5D%5Bdata%5D=references&columns%5B13%5D%5Bname%5D=&columns%5B13%5D%5Bsearchable%5D=true&columns%5B13%5D%5Borderable%5D=true&columns%5B13%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B13%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B14%5D%5Bdata%5D=discovered_date&columns%5B14%5D%5Bname%5D=&columns%5B14%5D%5Bsearchable%5D=true&columns%5B14%5D%5Borderable%5D=true&columns%5B14%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B14%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B15%5D%5Bdata%5D=open_status&columns%5B15%5D%5Bname%5D=&columns%5B15%5D%5Bsearchable%5D=true&columns%5B15%5D%5Borderable%5D=true&columns%5B15%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B15%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B16%5D%5Bdata%5D=hackerone_report_id&columns%5B16%5D%5Bname%5D=&columns%5B16%5D%5Bsearchable%5D=true&columns%5B16%5D%5Borderable%5D=false&columns%5B16%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B16%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B17%5D%5Bdata%5D=extracted_results&columns%5B17%5D%5Bname%5D=&columns%5B17%5D%5Bsearchable%5D=true&columns%5B17%5D%5Borderable%5D=true&columns%5B17%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B17%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B18%5D%5Bdata%5D=curl_command&columns%5B18%5D%5Bname%5D=&columns%5B18%5D%5Bsearchable%5D=true&columns%5B18%5D%5Borderable%5D=true&columns%5B18%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B18%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B19%5D%5Bdata%5D=matcher_name&columns%5B19%5D%5Bname%5D=&columns%5B19%5D%5Bsearchable%5D=true&columns%5B19%5D%5Borderable%5D=true&columns%5B19%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B19%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B20%5D%5Bdata%5D=request&columns%5B20%5D%5Bname%5D=&columns%5B20%5D%5Bsearchable%5D=false&columns%5B20%5D%5Borderable%5D=true&columns%5B20%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B20%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B21%5D%5Bdata%5D=response&columns%5B21%5D%5Bname%5D=&columns%5B21%5D%5Bsearchable%5D=false&columns%5B21%5D%5Borderable%5D=true&columns%5B21%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B21%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B22%5D%5Bdata%5D=template&columns%5B22%5D%5Bname%5D=&columns%5B22%5D%5Bsearchable%5D=false&columns%5B22%5D%5Borderable%5D=true&columns%5B22%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B22%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B23%5D%5Bdata%5D=template_url&columns%5B23%5D%5Bname%5D=&columns%5B23%5D%5Bsearchable%5D=false&columns%5B23%5D%5Borderable%5D=true&columns%5B23%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B23%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B24%5D%5Bdata%5D=template_id&columns%5B24%5D%5Bname%5D=&columns%5B24%5D%5Bsearchable%5D=false&columns%5B24%5D%5Borderable%5D=true&columns%5B24%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B24%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B25%5D%5Bdata%5D=impact&columns%5B25%5D%5Bname%5D=&columns%5B25%5D%5Bsearchable%5D=false&columns%5B25%5D%5Borderable%5D=true&columns%5B25%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B25%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B26%5D%5Bdata%5D=remediation&columns%5B26%5D%5Bname%5D=&columns%5B26%5D%5Bsearchable%5D=false&columns%5B26%5D%5Borderable%5D=true&columns%5B26%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B26%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B27%5D%5Bdata%5D=is_gpt_used&columns%5B27%5D%5Bname%5D=&columns%5B27%5D%5Bsearchable%5D=false&columns%5B27%5D%5Borderable%5D=true&columns%5B27%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B27%5D%5Bsearch%5D%5Bregex%5D=false&order%5B0%5D%5Bcolumn%5D=7&order%5B0%5D%5Bdir%5D=desc&start=0&length=50&search%5Bvalue%5D=http_url%3D{subdomain_name}'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()['data']


# A duplicate vuln is the same if has the same title and url and sometimes
# same vulnerable parameter
def removeAndJoinDuplicateVulns(dict):
    re_parameter = r"Vulnerable Parameter:\s*(\S+)"
    re_payload = r"Payload: Reflected Payload in Attribute: (\S+)"
    for item in dict:
        first_dalfox = True
        first_dalfox_element = None
        dalfox_count =  0
        indices_to_remove = []
        for idx, vuln in enumerate(item['subdomain']['vulnerabilities']):
            source = vuln['source']
            # dalfox filtering
            if source == 'dalfox':
                dalfox_count += 1
                clean_url = vuln['affected_url'].split('?')[0]
                if re.search(re_parameter, vuln['description']):
                        vulnerable_parameter = re.search(re_parameter, vuln['description']).group(1)
                if re.search(re_payload, vuln['description']):
                        payload = re.search(re_payload, vuln['description']).group(1)
                if first_dalfox:
                    first_dalfox = False
                    first_dalfox_element = vuln
                    first_dalfox_element['payloads'] = []
                    first_dalfox_element['vulnerable_parameter'] = vulnerable_parameter
                    first_dalfox_element['payloads'].append(payload)
                    first_dalfox_element['clean_url'] = clean_url
                else:
                    if clean_url == first_dalfox_element['clean_url'] and first_dalfox_element['vulnerable_parameter'] == vulnerable_parameter:
                        first_dalfox_element['payloads'].append(payload)
                    indices_to_remove.append(idx)
            # end dalfox filtering
        for index in sorted(indices_to_remove, reverse=True):
            del item['subdomain']['vulnerabilities'][index]
    return dict
# for some reason or a rengine's bug sometimes you have duplicated subdomains with no info
def removeDuplicatedSubdomains(dict):
    subdomain_dict = {}
    for item in dict:
        subdomain = item["name"]
        
        if subdomain not in subdomain_dict:
            subdomain_dict[subdomain] = item
        else:
            current_entry = subdomain_dict[subdomain]
            if (item["http_status"] != 0 or item["content_length"] != 0 or item["ip_addresses"]):
                subdomain_dict[subdomain] = item

    return list(subdomain_dict.values())

    