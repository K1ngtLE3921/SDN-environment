import time
import fcntl
import socket
import struct
import logging
from scapy.all import rdpcap
from scapy.all import RandMAC
from scapy.sendrecv import sendp
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP

def reader(pcap_file):
    try:
        packets = rdpcap(pcap_file)  # Read packets from the pcap file
        protocol_counts = {}  # Dictionary to count packets for each protocol

        # Initialize protocol counts
        protocols = ["Ethernet", "IP", "UDP", "BOOTP", "DHCP", "ARP"]
        for protocol in protocols:
            protocol_counts[protocol] = 0

        # Count occurrences of each protocol
        for pkt in packets:
            if pkt.haslayer(Ether):
                protocol_counts["Ethernet"] += 1
            if pkt.haslayer(IP):
                protocol_counts["IP"] += 1
            if pkt.haslayer(UDP):
                protocol_counts["UDP"] += 1
            if pkt.haslayer(BOOTP):
                protocol_counts["BOOTP"] += 1
            if pkt.haslayer(DHCP):
                protocol_counts["DHCP"] += 1
            if pkt.haslayer(ARP):
                protocol_counts["ARP"] += 1

        # Display results
        print(f"Total packets in {pcap_file}: {len(packets)}")
        print("Packet counts by protocol:")
        for protocol, count in protocol_counts.items():
            print(f"- {protocol}: {count}")

    except FileNotFoundError:
        print(f"Error: File {pcap_file} not found.")
    except Exception as e:
        print(f"An error occurred while reading the pcap file: {e}")

# Example usage
if __name__ == "__main__":
    pcap_file_path = "/home/akd/Desktop/Envrionment/DAST tool/SDN-environment/network_traffic.pcap"  # Replace with the path to your pcap file
    reader(pcap_file_path)