import requests, pickle, pathlib, re
from datetime import datetime

pattern_expiration = r"expires=([a-zA-Z]+,\s\d{2}\s[a-zA-Z]+\s\d{4}\s\d{2}:\d{2}:\d{2}\s\w{3})"

def authorize(baseUrl, username, password):
        try:
            if(checkConnection(baseUrl)):
                loginUrl = baseUrl + '/login/'
                s = requests.Session()
                s.cookies.set("hostname", baseUrl)
                r1 = s.get(loginUrl, verify=False)
                csrf_token = r1.cookies['csrftoken']
                r2 = s.post(loginUrl, data=dict(username=username,password=password,csrfmiddlewaretoken=csrf_token,next='/'), headers=dict(Referer=loginUrl), verify=False)
                # expiration = re.search(pattern_expiration, r2.headers['Set-Cookie']).group(1)
                # expiration_unix = datetime.strptime(expiration, "%a, %d %b %Y %H:%M:%S %Z").timestamp()
                # s.cookies.set("expiration", expiration)  
                # s.cookies.set("expiration_unix", expiration_unix) 
                #Lets make sure everything went okay, and save the session if it has
                if('Invalid username or password.' in r2.text):
                    print('Invalid username or password!')
                elif(r2.status_code == 200):
                    print("AUTHORIZED - Saving session into .rengineSession file")
                    #Save session
                    with open('.rengineSession', 'wb') as f:
                        pickle.dump(s, f)
                    print("SAVED")
                else:
                    print('ERROR AUTHORIZING - Check your username/password and base URL.  Status Code: ' + r2.status_code)
            else:
               print("Error connecting to the rengine instance")
               return 
        except Exception as error:
            print('ERROR!')
            print(error)
            
def getSession():
    try:
        with open('.rengineSession', 'rb') as f:
            session = pickle.load(f)
        if(not checkConnection(session.cookies['hostname'])):
            print("Error connecting to the rengine instance")
            return False
        elif(checkSessionHasExpired(session)):
            print("Session has expired, please Log In")
            return False
        return session
    except FileNotFoundError:
        return False


def deleteSession():
    pathlib.Path.unlink('.rengineSession')
    print('Deleted session file')
    
def checkSessionHasExpired(s):
    for cookie in s.cookies:
        if cookie.name == 'sessionid':
            expiration = cookie.expires
            now = int(datetime.now().timestamp())
            return(now > expiration)
        
def checkConnection(url):
    try:
        response = requests.get(url, verify=False)
        return response.ok
    except:
        return False