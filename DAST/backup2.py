from scapy.all import rdpcap, RandMAC, sendp
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from collections import Counter, defaultdict

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

def detect_arp_poisoning(pcap_file):
    try:
        packets = rdpcap(pcap_file)  # Read packets from the pcap file
        arp_replies = defaultdict(list)  # Track identical ARP reply messages and the packets

        # Populate the map with ARP reply packet details
        for pkt in packets:
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply (op=2)
                message = f"{pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"
                arp_replies[message].append(pkt)

        # Detect ARP reply messages that appear more than 5 times
        print("\nARP Poisoning Detection:")
        warning_issued = False
        for message, packets in arp_replies.items():
            if len(packets) > 5:
                warning_issued = True
                print(f"Warning: Potential ARP poisoning detected! Message '{message}' appears {len(packets)} times.")
                print("Potential ARP poisoning packets:")
                for pkt in packets[:5]:  # Print up to 5 packets
                    print(f"  - {pkt.summary()}")

        if not warning_issued:
            print("No ARP poisoning detected.")

    except FileNotFoundError:
        print(f"Error: File {pcap_file} not found.")
    except Exception as e:
        print(f"An error occurred while analyzing the pcap file: {e}")

def send_dhcp_discover(target_ip, target_mac):
    try:
        dhcp_discover = (
            Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst=target_ip) /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=RandMAC()) /
            DHCP(options=[("message-type", "discover"), "end"])
        )
        sendp(dhcp_discover, iface="h1-eth0", verbose=False)  # Send the packet via the network interface
        print("DHCP Discover packet sent!")
    except Exception as e:
        print(f"An error occurred while sending DHCP Discover: {e}")

if __name__ == "__main__":
    while True:
        print("\nSelect an option:")
        print("1. Reader (Count protocols)")
        print("2. Detect DHCP Poisoning")
        print("3. Detect ARP Poisoning")
        print("4. Send DHCP Discover")
        print("Type 'exit' to quit.")
        choice = input("Enter your choice: ").strip()

        if choice.lower() == 'exit':
            print("Exiting the program.")
            break

        if choice in ['1', '2', '3']:
            pcap_file_path = input("Enter the path to the pcap file: ").strip()

            if choice == '1':
                reader(pcap_file_path)
            elif choice == '2':
                detect_dhcp_poisoning(pcap_file_path)
            elif choice == '3':
                detect_arp_poisoning(pcap_file_path)

        elif choice == '4':
            target_ip = input("Enter the target IP address: ").strip()
            target_mac = input("Enter the target MAC address: ").strip()
            send_dhcp_discover(target_ip, target_mac)

        else:
            print("Invalid option. Please try again.")