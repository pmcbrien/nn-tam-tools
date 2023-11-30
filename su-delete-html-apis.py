import csv
import subprocess
import requests
import lxml.html

cust_url="https://XYZ123.noname.io"
jwt="PUT YOUR JWT HERE"

#login to NN as SU and use web dev tools to get the JWT for the user
#goto the api inventory section and export only the APIs you want to delete Host/Path/Method in the export.csv



# Read CSV file and process each row, skipping the header
with open('export.csv', 'r') as csvfile:
    csv_reader = csv.DictReader(csvfile)
    
    # Skip the header
    next(csv_reader, None)
    
    for row in csv_reader:
        #print(row)
        host = row['\ufeff"Host"']
        path = row['Path']
        method = row['Method']
        if method.upper() == 'GET':
            #print(row)
            #build command to check if html
            api_url = f"https://{host}{path}"

            headers = {"Content-Type": "charset=utf-8",
                        "Transfer-Encoding": "chunked",
                        "User-Agent": "nn-inv.py API inventory script"
                    }
            print(f"hitting api endpoint " + api_url)
            try:
                response_from_api = requests.get(api_url, timeout=5)
                
                print(f"Got back HTTP status code : {response_from_api.status_code}")
                
                if ( lxml.html.fromstring(response_from_api.text).find('.//*') == None ):
                    #print ("NOT HTML could be an API so skipping")
                    #print(response_from_api.text)
                    print("\n")
                else:
                    print ("HTML returned. Deleting the API.")
                    #print(response_from_api.text[:20])
                    
                    # Build curl command to delete the api as a SU
                    curl_command_delete_api = build_curl_command(host, path, method)

                    # Print or execute the curl command
                    print(curl_command_delete_api)

                    # If you want to execute the curl command, uncomment the line below
                    subprocess.run(curl_command_delete_api, shell=True)
            except:
                pass

# Function to build curl command
def build_curl_command(host, path, method):

    return "curl '"+str(cust_url)+"/backend/delete-api' \
  -H 'authority: "+str(cust_url)+"' \
  -H 'accept: application/json, text/plain, */*' \
  -H 'accept-language: en-US,en;q=0.9' \
  -H 'authorization: Bearer " + str(jwt)+ "' \
  -H 'content-type: application/json' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-fetch-dest: empty' \
  -H 'sec-fetch-mode: cors' \
  -H 'sec-fetch-site: same-origin' \
  -H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36' \
  --data-raw '"'{"host":"'+str(host)+'","method":"'+str(method)+'","path":"'+str(path)+'"}'"'"