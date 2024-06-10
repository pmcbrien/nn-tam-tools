def response(flow):
    print("\n\n")
    print("="*50)
    print(flow.request.method + " " + flow.request.path + " " + flow.request.http_version)

    print("\n-----" + "Request headers: -----")
    
    for k, v in flow.request.headers.items():
        print("%-20s: %s" % (k.upper(), v))
    
    print("\n----- Request Body: ----- ")
    print(flow.request.content)

    print("\n-----" + "Response headers: -----")
    for k, v in flow.response.headers.items():
        print("%-20s: %s" % (k.upper(), v))
        #print("-"*5 + "request headers:")

    print("\n----- Response Body: -----")
    print(flow.response.content)
