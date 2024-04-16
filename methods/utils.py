import json



def cleanUselessStuffFromDict(dict):
    for item in dict:
        item['subdomain'].pop('id')
    return dict

def prettyPrintJSON(dict):
    return json.dumps(dict, indent=4)


def cleanUselessStuffFromDict(dict, keys):
    cleaned = [dict.pop(key) for key in keys]
    return cleaned