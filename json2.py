from scapy.all import rdpcap
import json
import os

packet_data_list = []

def write_to_json():
    folder_path = 'json_file'
    os.makedirs(folder_path, exist_ok=True)

    # Specify the full path to the json file within the 'json_file' folder
    file_path = os.path.join(folder_path, 'packet_data.json')
    with open(file_path, "w") as json_file:
        json.dump(packet_data_list, json_file, indent=4)
    

def process_packet(packet):
    # Your packet processing logic goes here
    #print(packet.summary())  # For demonstration purposes, printing packet summary
    packet_data_list.append(packet.summary())

def read_pcap():
    file_path = r"C:\Users\DELL\Downloads\python_app-Copy\uploads\upload.pcap"
    packets = rdpcap(file_path)
    for packet in packets:
        process_packet(packet)

    # Move this outside the loop to write the JSON file after processing all packets
    write_to_json()

# Example usage

