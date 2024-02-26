import re

#json_line = 'Ether / IP / TCP 8.8.4.4:https > 10.1.0.149:56906 SA'
json_file = r"C:\Users\DELL\Downloads\python_app-copy\json_file\packet_data.json"

with open(json_file) as f:
        lines = f.readlines()

for line in lines:
    if "IP" in line and not "IPv6" in line:
        src_ip_match = re.search(r'TCP (\S+):', line)




        if src_ip_match:
            extracted_string = src_ip_match.group(1)
            print(f"Source IP: {extracted_string}")
        else:
            print("No match found.")