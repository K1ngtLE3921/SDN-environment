from scapy.all import rdpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from collections import Counter

def reader(pcap_file):
    try:
        packets = rdpcap(pcap_file)  # Read packets from the pcap file
        protocol_counts = {}  # Dictionary to count packets for each protocol

        # Initialize protocol counts
        protocols = ["Ethernet", "IP", "UDP", "BOOTP", "DHCP"]
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

        # Display results
        print(f"Total packets in {pcap_file}: {len(packets)}")
        print("Packet counts by protocol:")
        for protocol, count in protocol_counts.items():
            print(f"- {protocol}: {count}")

    except FileNotFoundError:
        print(f"Error: File {pcap_file} not found.")
    except Exception as e:
        print(f"An error occurred while reading the pcap file: {e}")

def detect_dhcp_poisoning(pcap_file):
    try:
        packets = rdpcap(pcap_file)  # Read packets from the pcap file
        dhcp_sources = []
        suspicious_packets = []

        # Extract source IPs from DHCP packets and save packet info
        for pkt in packets:
            if pkt.haslayer(DHCP):
                if pkt.haslayer(IP):
                    dhcp_sources.append(pkt[IP].src)
                    suspicious_packets.append(pkt.summary())

        # Count occurrences of each source IP
        source_counts = Counter(dhcp_sources)

        # Detect potential DHCP poisoning
        print("\nDHCP Poisoning Detection:")
        for source, count in source_counts.items():
            if count > 10:
                print(f"Warning: Potential DHCP poisoning detected! Source {source} appears {count} times.")
                print("Potential DHCP poisoning packets:")
                for pkt_info in suspicious_packets[:5]:  # Print up to 5 packets
                    print(f"  - {pkt_info}")

        if not any(count > 10 for count in source_counts.values()):
            print("No DHCP poisoning detected.")

    except FileNotFoundError:
        print(f"Error: File {pcap_file} not found.")
    except Exception as e:
        print(f"An error occurred while analyzing the pcap file: {e}")

# Example usage
if __name__ == "__main__":
    pcap_file_path = "/home/akd/Desktop/Envrionment/DAST tool/SDN-environment/network_traffic.pcap"  # Replace with the path to your pcap file
    reader(pcap_file_path)
    detect_dhcp_poisoning(pcap_file_path)