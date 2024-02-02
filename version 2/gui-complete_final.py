import tkinter as tk
from tkinter import scrolledtext, filedialog
from scapy.all import rdpcap, TCP, DHCP, IP

def extract_three_way_handshake(packets, src_ip, dst_ip, gui, inbetween_ip):
    syn_packet = None
    syn_ack_packet = None
    ack_packet = None

    for packet in packets:
        if IP in packet and TCP in packet:
            if packet[TCP].flags.S and packet[IP].src == src_ip and (packet[IP].dst == "3.15.254.99" or packet[IP].dst == "142.250.70.99" or packet[IP].dst == "17.57.145.133" or packet[IP].dst == "102.17.24.14" or packet[IP].dst == inbetween_ip):                                     
                syn_packet = packet
                gui.append_text("\nSYN Packet:")
                gui.append_text(str(syn_packet.summary()))
                
            elif packet[TCP].flags.SA and packet[IP].dst == src_ip and (packet[IP].src == "3.15.254.99" or packet[IP].src == "142.250.70.99" or packet[IP].src == "17.57.145.133" or packet[IP].src == "102.17.24.14" or packet[IP].src == inbetween_ip):
                syn_ack_packet = packet
                gui.append_text("\nSYN-ACK Packet Received:")
                gui.append_text(str(syn_ack_packet.summary()))
                
            elif packet[TCP].flags.A and packet[IP].src == src_ip and (packet[IP].dst == "3.15.254.99" or packet[IP].dst == "142.250.70.99" or packet[IP].dst == "17.57.145.133" or packet[IP].dst == "102.17.24.14" or packet[IP].dst == inbetween_ip):
                ack_packet = packet
                gui.append_text("\nACK Packet Received:")
                gui.append_text(str(ack_packet.summary()))

    return syn_packet, syn_ack_packet, ack_packet

def analyze_pcap(file_path, gui):
    dhcp_steps = {1, 2, 3, 5}  
    observed_steps = set()

    packets = rdpcap(file_path)

    for packet in packets:
        if DHCP in packet:
            dhcp_message_type = packet[DHCP].options[0][1]
            observed_steps.add(dhcp_message_type)
            process_packet(packet, gui)

    missing_steps = dhcp_steps - observed_steps

    if missing_steps:
        gui.append_text("DHCP Connection is Unsuccessful. Missing steps:")
        for missing_step in missing_steps:
            if missing_step == 1:
                gui.append_text("DHCP Discover")
            elif missing_step == 2:
                gui.append_text("DHCP Offer")
            elif missing_step == 3:
                gui.append_text("DHCP Request")
            elif missing_step == 5:
                gui.append_text("DHCP Acknowledgment")
    else:
        gui.append_text("DHCP Connection is Successful.")

def process_packet(packet, gui):
    if DHCP in packet:
        dhcp_message_type = packet[DHCP].options[0][1]

        if dhcp_message_type == 1:
            gui.append_text("DHCP Discover:")
        elif dhcp_message_type == 2:
            gui.append_text("DHCP Offer:")
        elif dhcp_message_type == 3:
            gui.append_text("DHCP Request:")
        elif dhcp_message_type == 5:
            gui.append_text("DHCP Acknowledgment:")

        src_ip = packet[IP].src if IP in packet else None
        dst_ip = packet[IP].dst if IP in packet else None
        protocol = packet[IP].proto if IP in packet else None

        gui.append_text(f"Source IP: {src_ip}\tDestination IP: {dst_ip}\tProtocol: {protocol}")

class PacketAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Analyzer")


        self.source_ip_entry_label = tk.Label(root, text="User IP (Phone/Computer)")
        self.source_ip_entry_label.pack(pady=5)
        self.source_ip_entry = tk.Entry(root, width=20)
        self.source_ip_entry.insert(0, "192.168.8.160")
        self.source_ip_entry.pack(pady=5)

        self.destination_ip_entry_label = tk.Label(root, text="Router IP")
        self.destination_ip_entry_label.pack(pady=5)
        self.destination_ip_entry = tk.Entry(root, width=20)
        self.destination_ip_entry.insert(0, "192.168.8.1")
        self.destination_ip_entry.pack(pady=5)


        self.inbetween_ip_entry_label = tk.Label(root, text="SYN, SYN-ACK, ACK IP")
        self.inbetween_ip_entry_label.pack(pady=5)
        self.inbetween_ip_entry = tk.Entry(root, width=20)
        self.inbetween_ip_entry.insert(0, "192.168.8.1")
        self.inbetween_ip_entry.pack(pady=5)

        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.pack(pady=5)

        self.analyze_button = tk.Button(root, text="Analyze Packets", command=self.analyze_packets)
        self.analyze_button.pack(pady=10)
        
        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
        self.text_area.pack(padx=10, pady=10)

    def append_text(self, text, bold=False, font_size=12):
        tag = "bold" if bold else ""
        self.text_area.tag_configure(tag, font=("TkDefaultFont", font_size, "bold" if bold else "normal"))
        self.text_area.insert(tk.END, text + "\n")
        self.text_area.yview(tk.END)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        self.pcap_file_path = file_path
        self.append_text(f"Selected PCAP file: {file_path}\n")

    def analyze_packets(self):
        src_ip = self.source_ip_entry.get()
        dst_ip = self.destination_ip_entry.get()
        inbetween_ip = self.destination_ip_entry.get()

        if not hasattr(self, 'pcap_file_path'):
            self.append_text("Please select a PCAP file.")
            return

        pcap_file = self.pcap_file_path

        packets = rdpcap(pcap_file)

        # Redirecting prints to the GUI
        def custom_print(text):
            self.append_text(text)

        # Redirecting prints to the GUI
        print = custom_print

        # DHCP
        analyze_pcap(pcap_file, self)

        # Three-Way Handshake
        syn_packet, syn_ack_packet, ack_packet = extract_three_way_handshake(packets, src_ip, dst_ip, self, inbetween_ip)
        if syn_packet is None:
            print("\nWarning: SYN packet in the Three-Way Handshake not found.")
        elif syn_ack_packet is None:
            print("\nWarning: SYN-ACK packet in the Three-Way Handshake not found.")
        elif ack_packet is None:
            print("\nWarning: ACK packet in the Three-Way Handshake not found.")
        else:
            print("\nThree-way Handshake Successful")

def main():
    root = tk.Tk()
    app = PacketAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()





#kavindu baliloues : 192.168.8.160 --
#kavindu nandanas : 192.168.8.171	0 0

#sudeera ayya belilous: 192.168.8.190---
#suddera ayya test2: 192.168.8.158 ----