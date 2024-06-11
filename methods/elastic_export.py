from elasticsearch import Elasticsearch
from datetime import datetime
from urllib.parse import urlparse, urlunparse
import hashlib, re

def normalize(host):
    port = 9200
    if not re.match(r'http[s]?://', host):
        host = 'http://' + host

    parsed_url = urlparse(host)
    
    netloc = parsed_url.hostname
    if parsed_url.port is None:
        netloc += f':{port}'
    else:
        netloc += f':{port}'
        
    normalized_url = urlunparse((
        'http',
        netloc,
        parsed_url.path or '',
        parsed_url.params or '',
        parsed_url.query or '',
        parsed_url.fragment or ''
    ))

    return normalized_url
    
def indexDocument(es, index, dict):
    for item in dict:
        item['subdomain'].update({"@timestamp": datetime.now()})
        id = hashlib.md5(item['subdomain']['subdomain_name'].encode()).hexdigest()
        resp = es.index(index=index, document=item['subdomain'], id=id)
                
def initialize(host, username, password):
    normalized_host = normalize(host)
    es = Elasticsearch(normalized_host, basic_auth=(username, password), verify_certs=False)
    return es