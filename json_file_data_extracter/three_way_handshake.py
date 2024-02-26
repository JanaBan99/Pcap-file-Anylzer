import json
import re
global source_ip

def search_three_way_handshake():
    json_file = r"C:\Users\DELL\Downloads\python_app-Copy\json_file\packet_data.json"
    with open(json_file) as f:
        lines = f.readlines()

    found_s = found_sa = found_a = False
    print_statements = []

    for line in lines:
        if  "S" in line and "A" not in line:
            found_s = True
            #print("S found")
            src_ip_match = re.search(r'TCP (\S+):', line)
            if src_ip_match:
                    source_ip = src_ip_match.group(1)
                    #print(f"Source IP: {extracted_string}")
            #src_ip_match = re.search(r'TCP (.*?):', line)
            #src_ip = src_ip_match.group()
            #print(f"Source IP: {src_ip}")
            
        elif "S" in line and "A" in line:
            found_sa = True
            #print(line)
            #print("SA found")
        elif "A" in line:
            found_a = True
            #print("A found")

    if found_s and found_sa and found_a:
        #print(f"Three-way handshake found for {extracted_string}")
        #print(f"Three-way handshake found")
        statement="Three-way handshake for {source_ip} found in the wireshark file"
        print_statements.append(statement)

        return print_statements
    else:
        #print(f"No complete three-way handshake found for {extracted_string}")
        print_statements.append("Three-way handshake not found in the wireshark file")
        #return print_statements

# Example usage
#user_ip = "192.168.8.160"
#json_file = r"C:\Users\DELL\Downloads\python app\json_file\packet_data.json"
#search_three_way_handshake()
