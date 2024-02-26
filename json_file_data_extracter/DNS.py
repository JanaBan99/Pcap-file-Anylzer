import json

def DNS():
    json_file = r"C:\Users\DELL\Downloads\python_app-Copy\json_file\packet_data.json"
    with open(json_file) as f:
        lines = f.readlines()
        

    DNS_Qry = DNS_Ans = False
    print_statements = []

    for line in lines:
        if "DNS Qry" in line :
            DNS_Qry = True
            #print(line)
        elif "DNS Ans" in line :
            DNS_Ans = True
            #print(line)


    if DNS_Ans and DNS_Qry:
        #print(f"################## DNS request and DNS Responses found in the Wireshark file ###################")
        print_statements.append("DNS found in the wireshark file")
        return print_statements
    else:
        #print(f"################## DNS request and DNS Responses not found in the Wireshark file ###############")
        print_statements.append("DNS not found in the wireshark file")
        return print_statements


#DNS()
