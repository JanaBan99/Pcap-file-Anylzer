from scapy.all import rdpcap
import json
import os
packet_data_list = []

def write_to_json():
    folder_path = 'json_file'
    os.makedirs(folder_path, exist_ok=True)

    # Specify the full path to the json file within the 'json_file' folder
    file_path = os.path.join(folder_path, 'packet_data.json')
    with open("packet_data.json", "w") as json_file:
        json.dump(packet_data_list, json_file, indent=4)


def process_packet(packet):
    # Your packet processing logic goes here
    print(packet.summary())  # For demonstration purposes, printing packet summary
    packet_data_list = packet.summary()
    write_to_json()
    
def main(file_path):
    packets = rdpcap(file_path)
    for packet in packets:
        process_packet(packet)

# Example usage
file_path = r"C:\Users\DELL\Downloads\python_app-copy\uploads\upload.pcap"
main(file_path)