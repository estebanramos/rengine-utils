import methods.target as target

def run_scan(s, name, project_name):
    target_id = target.findTargetIdByName(name, s)['target_id']
    baseUrl = s.cookies['hostname']
    csrf_token = s.cookies['csrftoken']
    runScanEndpoint = baseUrl + f'/scan/{project_name.lower()}/target/start/{target_id}'
    headers = {'Referer': runScanEndpoint, 'Content-type': 'application/x-www-form-urlencoded', 'X-CSRFToken': csrf_token}
    data = {"csrfmiddlewaretoken": csrf_token, "scan_mode": 6, "importSubdomainTextArea": "", "outOfScopeSubdomainTextarea": "", "filterPath": ""}
    print(runScanEndpoint)
    r = s.post(runScanEndpoint, headers=headers, data=data, verify=False)
    if r.status_code == 200 or r.status_code == 302:
        print("Running scan...")
