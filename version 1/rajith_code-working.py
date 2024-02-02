from scapy.all import rdpcap, TCP, DHCP,IP


def extract_three_way_handshake(packets, src_ip, dst_ip):
    syn_packet = None
    syn_ack_packet = None
    ack_packet = None

    for packet in packets:
        if IP in packet and TCP in packet:
            
                if packet[TCP].flags.S and packet[IP].src == src_ip and (packet[IP].dst == "3.15.254.99" or packet[IP].dst == "142.250.70.99"):                                     #ACK, SCK-ACK all has s flags in them. use something else to recognize it
                    syn_packet = packet
                    print("\nSYN Packet:")
                    print(syn_packet.summary())
                

                    # Your modification to print SYN-ACK Packet when received
                elif packet[TCP].flags.SA and packet[IP].dst == src_ip and (packet[IP].src == "3.15.254.99" or packet[IP].src == "142.250.70.99"):
                    syn_ack_packet = packet
                    print("\nSYN-ACK Packet Received:")
                    print(syn_ack_packet.summary())

                

                
                elif packet[TCP].flags.A and packet[IP].src == src_ip and (packet[IP].dst == "3.15.254.99" or packet[IP].dst == "142.250.70.99"):
                    ack_packet = packet

                    print("\nACK Packet Received:")
                    print(ack_packet.summary())

    return syn_packet, syn_ack_packet, ack_packet



def process_packet(packet):
    if DHCP in packet:
        dhcp_message_type = packet[DHCP].options[0][1]

        if dhcp_message_type == 1:
            print("DHCP Discover:")
        elif dhcp_message_type == 2:
            print("DHCP Offer:")
        elif dhcp_message_type == 3:
            print("DHCP Request:")
        elif dhcp_message_type == 5:
            print("DHCP Acknowledgment:")

        # Extracting relevant information
        src_ip = packet[IP].src if IP in packet else None
        dst_ip = packet[IP].dst if IP in packet else None
        protocol = packet[IP].proto if IP in packet else None

        # Print the information in a tabular format
        print(f"Source IP: {src_ip}\tDestination IP: {dst_ip}\tProtocol: {protocol}")

def analyze_pcap(file_path):
    dhcp_steps = {1, 2, 3, 5}  # DHCP message types to check
    observed_steps = set()

    packets = rdpcap(file_path)

    for packet in packets:
        if DHCP in packet:
            dhcp_message_type = packet[DHCP].options[0][1]
            observed_steps.add(dhcp_message_type)
            process_packet(packet)

    missing_steps = dhcp_steps - observed_steps

    if missing_steps:
        print("DHCP Connection is Unsuccessful. Missing steps:")
        for missing_step in missing_steps:
            if missing_step == 1:
                print("DHCP Discover")
            elif missing_step == 2:
                print("DHCP Offer")
            elif missing_step == 3:
                print("DHCP Request")
            elif missing_step == 5:
                print("DHCP Acknowledgment")
    else:
        print("DHCP Connection is Successful.")


    
    
def main():
    pcap_file = r'C:\Users\DELL\Desktop\nvison\wifi work\read\rajith ayya work\packetcap.pcap'              #kavindu
    #pcap_file = r'C:\Users\DELL\Downloads\wireshark files\Sudeera_Belilios_01-10-24_12h-39m-50s\packetcap.pcap'         #Sudira ayya
    src_ip = '192.168.8.160'                            #'192.168.8.160' - K                       #'192.168.8.190' - S
    dst_ip = '192.168.8.1'
    target_ip = ['3.15.254.99','142.250.70.99']

    packets = rdpcap(pcap_file)

    # DHCP
    analyze_pcap(pcap_file)

    # Three-Way Handshake
    syn_packet, syn_ack_packet, ack_packet = extract_three_way_handshake(packets, src_ip, dst_ip)
    if syn_packet is None:
        #or syn_ack_packet is None or ack_packet is None:
        print("\nWarning: SYN packet in the Three-Way Handshake not found.")
    elif syn_ack_packet is None:
        print("\nWarning: SYN-ACK packet in the Three-Way Handshake not found.")
    elif ack_packet is None:
        print("\nWarning: ACK packet in the Three-Way Handshake not found.")
    else:
        print("\nThree way Handshake Sucessfull")


if __name__ == "__main__":
    main()
