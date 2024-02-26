import re
json_file = r"C:\Users\DELL\Downloads\python_app-copy\json_file\packet_data.json"

with open(json_file) as f:
        lines = f.readlines()

for line in lines:
    if "IP" in line and not "IPv6" in line:
        src_ip_match = re.search(r'TCP (.*?):', line)
        dst_ip_match = re.search(r'> (.*?):', line)
        if src_ip_match:
            src_ip = src_ip_match.group(1)
            print(f"Source IP: {src_ip}")
            
        if dst_ip_match:
            dst_ip = dst_ip_match.group(1)
            print(f"Destination IP: {dst_ip}\n")
            


