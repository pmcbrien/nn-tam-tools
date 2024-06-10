#mitmdump -q -v --set block_global=false -s parseheaders.py 

def response(flow):
    print("")
    print("="*50)
    #print("FOR: " + flow.request.url)
    print(flow.request.method + " " + flow.request.path + " " + flow.request.http_version)

    print("-"*5 + "request headers:")
    
    for k, v in flow.request.headers.items():
        print("%-20s: %s" % (k.upper(), v))
    
    print("Request Body: ")
    print(flow.request.content)

    print("-"*5 + "response headers:")
    for k, v in flow.response.headers.items():
        print("%-20s: %s" % (k.upper(), v))
        print("-"*5 + "request headers:")

    print("Response Body:")
    print(flow.response.content)
