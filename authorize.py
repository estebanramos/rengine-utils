import requests, pickle, pathlib



def authorize(baseUrl, username, password):
        try:
            loginUrl = baseUrl + '/login/'
            s = requests.Session()
            s.cookies.set("hostname", baseUrl, domain="local.local")
            r1 = s.get(loginUrl, verify=False)
            csrf_token = r1.cookies['csrftoken']
            r2 = s.post(loginUrl, data=dict(username=username,password=password,csrfmiddlewaretoken=csrf_token,next='/'), headers=dict(Referer=loginUrl), verify=False)
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
        except Exception as error:
            print('ERROR!')
            print(error)
            
def getSession():
        with open('.rengineSession', 'rb') as f:
            session = pickle.load(f)
        return session


def deleteSession():
    pathlib.Path.unlink('.rengineSession')
    print('Deleted session -- good on you for great security practices!')