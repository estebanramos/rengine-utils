from elasticsearch import Elasticsearch
from datetime import datetime
from urllib.parse import urlparse, urlunparse
import hashlib, re, ssl, socket, requests

def supports_ssl(host, port):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    try:
        conn.connect((host, port))
        conn.close()
        return True
    except Exception as e:
        return False
    
def normalize(host):
    port = 9200
    if not re.match(r'http[s]?://', host):
        host = 'http://' + host

    parsed_url = urlparse(host)
    netloc = parsed_url.hostname

    if supports_ssl(netloc, 443):
        scheme = 'https'
        port = 443
    else:
        scheme = 'http'
        if parsed_url.port is not None:
            port = parsed_url.port

    netloc = f"{netloc}:{port}"   
    normalized_url = urlunparse((
        scheme,
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
        try:
            resp = es.index(index=index, document=item['subdomain'], id=id)
        except ConnectionError:
            print("FAILED to connect to Elasticsearch instance: {}")
                
def initialize(host, username, password):
    normalized_host = normalize(host)
    es = Elasticsearch(normalized_host, basic_auth=(username, password), verify_certs=False)
    if es.ping():
        return es
    else:
        return