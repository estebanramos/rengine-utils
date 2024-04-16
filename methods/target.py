import methods.utils as utils


def generateSummaryByTargetName(name, s, project_name):
        target_id = findTargetIdByName(name, s)['target_id']
        subdomain_summary = getSubdomainsByTargetName(name, s, project_name)
        subdomain_list = subdomain_summary['subdomains']
        vulnerabilities_list = getVulnerabilitiesByTargetName(name, s)
        urls_list = getEndpointsByTargetName(name, s, project_name)
        for item in subdomain_list:
            for item2 in vulnerabilities_list:
                if item['subdomain']['subdomain_name'] == item2['subdomain']['name']:
                    item['subdomain']['vulnerabilities'] = item2['subdomain']['vulnerabilities']
            for item3 in urls_list:
                if 'urls' in item3.keys() and (item['subdomain']['subdomain_name'] == item3['subdomain_name']):
                    item['subdomain']['urls'] = item3['urls']
        for item in subdomain_list:
            utils.cleanUselessStuffFromDict(item['subdomain'], ['id'])
            print(utils.prettyPrintJSON(item))


def listVulnerabilitiesByTargetName(name, s):
    target_id = findTargetIdByName(name, s)['target_id']
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + f'/api/listVulnerability/?target_id={target_id}&format=datatables&search[value]=severity=Medium | severity=High | severity=Critical | severity=Low'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()
    root = {"domain": name, "subdomains": []}
    temporal = {}
    for item in j['data']:
        subdomain = item['subdomain']['name']
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

def getVulnerabilitiesByTargetName(name, s):
    target_id = findTargetIdByName(name, s)['target_id']
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + f'/api/listVulnerability/?target_id={target_id}&format=datatables&search[value]=severity=Medium | severity=High | severity=Critical | severity=Low'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()
    root = {"domain": name, "subdomains": []}
    temporal = {}
    for item in j['data']:
        subdomain = item['subdomain']['name']
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
    return root['subdomains']
        
def listEndpointsByTargetName(name, s, project_name):
    try:
        target_id = findTargetIdByName(name, s)['target_id']
    except:
        print("The target doesn't exists")
        return
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + f'/api/listEndpoints/?format=datatables&project={project_name}&target_id={target_id}'
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
    listIPsUrl = baseUrl + f'/api/listEndpoints/?format=datatables&project={project_name}&target_id={target_id}'
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
    root = { "subdomain": {
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
        
        
            

def listSubdomainsByTargetName(name, s, project):
    if TargetExists(name, s):
        target_id = findTargetIdByName(name, s)['target_id']
    else:
        print("Target doesn't exists!")
        return {}
    target_id = findTargetIdByName(name, s)['target_id']
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + f'/api/listDatatableSubdomain/?project={project.lower()}&target_id={target_id}&format=datatables'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()
    root = {"domain": name, "subdomains": []}
    temporal = []
    if not len(j['data']):
        print("Target exists but doesn't have subdomains associated. Be sure to scan it for subdomains")
        return {}
    for item in j['data']:
        subdomain = item['name']
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
                    ip_address = {"address": item2['address'], "ports": port_info}
                    ip_addresses.append(ip_address)

            i = {"subdomain": {
                "domain": name,
                "subdomain_name": subdomain,
                "ip_addresses": ip_addresses,
                "id": item['id']

            }
            }
            root['subdomains'].append(i)
            temporal.append(item['name'])
    for item in root['subdomains']:
        utils.cleanUselessStuffFromDict(item['subdomain'], ['id'])
        print(utils.prettyPrintJSON(item)+',')
        
def getSubdomainsByTargetName(name, s, project):
    if TargetExists(name, s):
        target_id = findTargetIdByName(name, s)['target_id']
    else:
        print("Target doesn't exists!")
        return {}
    target_id = findTargetIdByName(name, s)['target_id']
    baseUrl = s.cookies['hostname']
    listIPsUrl = baseUrl + f'/api/listDatatableSubdomain/?project={project}&target_id={target_id}&format=datatables'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()
    root = {"domain": name, "subdomains": []}
    temporal = []
    if not len(j['data']):
        print("Target exists but doesn't have subdomains associated. Be sure to scan it for subdomains")
        return {}
    for item in j['data']:
        subdomain = item['name']
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
                    ip_address = {"address": item2['address'], "ports": port_info}
                    ip_addresses.append(ip_address)

            i = {"subdomain": {
                "domain": name,
                "subdomain_name": subdomain,
                "ip_addresses": ip_addresses,
                "id": item['id']

            }
            }
            root['subdomains'].append(i)
            temporal.append(item['name'])
    return root
        
        
        
def findTargetIdByName(name, s):
    baseUrl= s.cookies['hostname']
    listIPsUrl= baseUrl + '/api/listTargets/?format=datatables'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()['data']
    for item in j:
        if item['name'] == name:
            i = {   'name':name,
                    'target_id': item['id']       
            }
            return i

def listTargets(s):
    baseUrl= s.cookies['hostname']
    listIPsUrl= baseUrl + '/api/listTargets/?format=datatables'
    csrf_token = s.cookies['csrftoken']
    headers = {'Referer': listIPsUrl,
               'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    r = s.get(listIPsUrl, headers=headers, verify=False)
    j = r.json()['data']
    for item in j:
        print(utils.prettyPrintJSON(item))
    print("\nIf you want a more clean output try using --clean")
    return j
    


def listCleanTargets(s):
    baseUrl= s.cookies['hostname']
    listIPsUrl= baseUrl + '/api/listTargets/?format=datatables'
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
    baseUrl= s.cookies['hostname']
    listIPsUrl= baseUrl + '/api/listTargets/?format=datatables'
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
            if item2['http_url'].strip('https://').split('/')[0] == item['subdomain']['subdomain_name']:
                i = {
                    "http_url": item2['http_url'],
                    "title": item2['page_title'],
                    "webserver": item2['webserver'],
                    "techs": item2["techs"]
                }
                if subdomainExistsInDict(subdomains_with_urls, item['subdomain']['subdomain_name']):
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
