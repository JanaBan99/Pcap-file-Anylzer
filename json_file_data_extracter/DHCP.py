import json
import webbrowser


def search_DHCP():
    json_file =r"C:\Users\DELL\Downloads\python_app-Copy\json_file\packet_data.json"
    with open(json_file) as f:
        lines = f.readlines()

    DHCP_Discover = DHCP_Offer = DHCP_Request = DHCP_Ack = False
    print_statements = []
    
    for line in lines:
        if "DHCP Discover" in line :
            DHCP_Discover = True
            #print("S found")
        elif "DHCP Offer" in line :
            DHCP_Offer = True
            #print(line)
            #print("SA found")
        elif "DHCP Request" in line:
            DHCP_Request = True
            #print("A found")
        elif "DHCP Ack" in line:
            DHCP_Ack = True
            #print("A found")

    if DHCP_Discover and DHCP_Offer and DHCP_Request and DHCP_Ack:
        #output_html = "templates\output.html"
        print_statements.append("DHCP found in the wireshark file")

        return print_statements

        #with open(output_html, "w") as output_file:
        #    output_file.write("<html><body>")
        #    output_file.write("<h2>DHCP found in the wireshark file</h2>")
        #    output_file.write("</body></html>")

        #webbrowser.open(output_html)'

    else:
        #print(f"##################  DHCP not found in the wireshark file  ##################")
        print_statements.append("DHCP not found in the wireshark file")

        return print_statements

# Example usage


#search_DHCP()
