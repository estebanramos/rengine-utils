import requests
from bs4 import BeautifulSoup


#This only returns the default project when requesting root path
def getDefaultProject(s):
    baseUrl= s.cookies['hostname']
    listIPsUrl= baseUrl + '/'
    csrf_token = s.cookies['csrftoken']
    r = s.get(listIPsUrl, verify=False, allow_redirects=False, headers={'Referer':'https://127.0.0.1/'})
    default_project = r.headers['location'].strip('/').split('/')[0]
    return default_project


#Parsing the HTML because there's not an API endpoint for projects and there not better way of doing it
def listProjects(s, project_name):
    baseUrl= s.cookies['hostname']
    listIPsUrl= baseUrl + f'/{project_name}/projects/'
    csrf_token = s.cookies['csrftoken']
    r = s.get(listIPsUrl, verify=False, allow_redirects=False, headers={'Referer':'https://127.0.0.1/'})
    html = r.text
    soup = BeautifulSoup(html, 'html.parser')
    dropdown_menu = soup.find('li', class_='dropdown').find('div', class_='dropdown-menu')
    elements = dropdown_menu.find_all('a')
    projects = []
    for element in elements:
        span = element.find('span')
        if span:
            projects.append(span.text.strip())
    return projects