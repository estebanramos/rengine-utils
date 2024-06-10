from elasticsearch import Elasticsearch
from datetime import datetime
import hashlib

def indexDocument(es, index, dict):
    for item in dict:
        item['subdomain'].update({"@timestamp": datetime.now()})
        id = hashlib.md5(item['subdomain']['subdomain_name'].encode()).hexdigest()
        resp = es.index(index=index, document=item['subdomain'], id=id)
                
def initialize(host, username, password):
    es = Elasticsearch(host, basic_auth=(username, password), verify_certs=False)
    return es