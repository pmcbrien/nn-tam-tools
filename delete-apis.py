import csv
import subprocess

cust_url="https://XYZ123.nonamesec.io"
jwt="PUT YOUR JWT HERE"

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

# Read CSV file and process each row, skipping the header
with open('export.csv', 'r') as csvfile:
    csv_reader = csv.DictReader(csvfile)
    
    # Skip the header
    next(csv_reader, None)
    
    for row in csv_reader:
        print(row)
        host = row['\ufeff"Host"']
        path = row['Path']
        method = row['Method']

        # Build curl command
        curl_command = build_curl_command(host, path, method)

        # Print or execute the curl command
        #print(curl_command)

        # If you want to execute the curl command, uncomment the line below
        subprocess.run(curl_command, shell=True)

