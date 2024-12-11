from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp, dhcp, udp
from ryu.lib.packet import ether_types
from scapy.utils import PcapWriter
import socket
import random
import os

def dhcp_option(tag, value):
    """
    Create a DHCP option with a specific tag and value.
    :param tag: The option tag (e.g., 1 for subnet mask).
    :param value: The option value in binary format.
    :return: A tuple representing the DHCP option.
    """
    return dhcp.option(tag=tag, value=value)


class DHCPServer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DHCPServer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.dhcp_server_ip = "192.168.227.1"  # DHCP Server IP
        self.dhcp_server_mac = '00:11:22:33:44:55'  # DHCP Server MAC
        self.ip_pool = self.generate_ip_pool()  # IP Pool
        self.mac_to_ip = {}  # MAC-to-IP mapping
        self.arp_table = {}  # IP-to-MAC mapping (ARP table)

        pcap_file = "network_traffic.pcap"
        self.pcap_writer = PcapWriter(pcap_file, append=True, sync=True)
        self.logger.info(f"PCAP file initialized at {os.path.abspath(pcap_file)}")

    def handle_arp_request(self, datapath, in_port, arp_pkt, eth):
        """Handle incoming ARP requests and generate ARP replies."""
        self.logger.info(f"Handling ARP request: src_ip={arp_pkt.src_ip}, dst_ip={arp_pkt.dst_ip}")
        
        # Update ARP table with source IP and MAC
        self.arp_table[arp_pkt.src_ip] = eth.src
        self.logger.info(f"Updated ARP table: {self.arp_table}")

        # Check if the destination IP is in the ARP table
        if arp_pkt.dst_ip in self.arp_table:
            dst_mac = self.arp_table[arp_pkt.dst_ip]
        else:
            # Respond with the DHCP server's MAC if it's the server's IP
            if arp_pkt.dst_ip == self.dhcp_server_ip:
                dst_mac = self.dhcp_server_mac
            else:
                self.logger.warning(f"Unknown ARP request for IP: {arp_pkt.dst_ip}")
                return

        # Create ARP reply
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype=eth.ethertype,
            dst=eth.src,
            src=dst_mac  # Use the resolved or server MAC
        ))
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=dst_mac,
            src_ip=arp_pkt.dst_ip,
            dst_mac=eth.src,
            dst_ip=arp_pkt.src_ip
        ))
        arp_reply.serialize()

        # Send ARP reply
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=arp_reply.data
        )
        datapath.send_msg(out)
        self.logger.info(f"ARP reply sent: src_ip={arp_pkt.dst_ip}, src_mac={dst_mac}")

    def handle_arp_reply(self, datapath, arp_pkt):
        """Update ARP table upon receiving an ARP reply."""
        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
        self.logger.info(f"ARP table updated with reply: {self.arp_table}")

    def generate_ip_pool(self):
        """Generate a pool of IP addresses within the range 192.168.1.1 to 192.168.1.255."""
        ip_pool = []
        for i in range(2, 255):  # Exclude the DHCP server IP (192.168.1.1)
            ip_pool.append(f"192.168.227.{i}")
        return ip_pool

    def assign_ip(self, mac_address):
        """Assign an IP address to a MAC address."""
        if mac_address in self.mac_to_ip:
            return self.mac_to_ip[mac_address]
        if not self.ip_pool:
            self.logger.warning("No IP addresses available in the pool!")
            return None
        assigned_ip = random.choice(self.ip_pool)
        self.ip_pool.remove(assigned_ip)
        self.mac_to_ip[mac_address] = assigned_ip
        return assigned_ip

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install a table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Add flow entries for DHCP and ARP
        self.add_dhcp_arp_flows(datapath)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_dhcp_arp_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Flow for DHCP Discover (client to server)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=socket.IPPROTO_UDP, udp_src=67, udp_dst=68)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 10, match, actions)

        # Flow for ARP requests (client to server)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_op=arp.ARP_REQUEST)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 10, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        self.save_packet_to_pcap(pkt)

        self.logger.info(f"Packet received: src_mac={eth.src}, dst_mac={eth.dst}, in_port={in_port}")

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore LLDP packets
            return

        # Handle ARP packets
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            if arp_pkt.opcode == arp.ARP_REQUEST:
                self.handle_arp_request(datapath, in_port, arp_pkt, eth)
            elif arp_pkt.opcode == arp.ARP_REPLY:
                self.handle_arp_reply(datapath, arp_pkt)
            return

        # Handle DHCP packets
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        if dhcp_pkt:
            self.logger.info(f"Handling DHCP packet: xid={dhcp_pkt.xid}, chaddr={dhcp_pkt.chaddr}")
            self.handle_dhcp(datapath, in_port, pkt, dhcp_pkt)
            return

        # Default behavior: flood packets
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def handle_arp_request(self, datapath, in_port, arp_pkt, eth):
        """Handle incoming ARP requests and generate ARP replies."""
        self.logger.info(f"Handling ARP request: src_ip={arp_pkt.src_ip}, dst_ip={arp_pkt.dst_ip}")
        
        # Update ARP table with source IP and MAC
        self.arp_table[arp_pkt.src_ip] = eth.src
        self.logger.info(f"Updated ARP table: {self.arp_table}")

        # Check if the destination IP is in the ARP table
        if arp_pkt.dst_ip in self.arp_table:
            dst_mac = self.arp_table[arp_pkt.dst_ip]
            self.logger.info(f"Resolved destination MAC for IP {arp_pkt.dst_ip}: {dst_mac}")
        else:
            # If it's the DHCP server's IP, use the server's MAC address
            if arp_pkt.dst_ip == self.dhcp_server_ip:
                dst_mac = self.dhcp_server_mac
                self.logger.info(f"Responding with DHCP server's MAC {dst_mac} for IP {arp_pkt.dst_ip}")
            else:
                # Log the unknown request for troubleshooting
                self.logger.warning(f"Unknown ARP request for IP: {arp_pkt.dst_ip}")
                return

        # Create ARP reply packet
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype=eth.ethertype,
            dst=eth.src,
            src=dst_mac  # Use resolved or server MAC
        ))
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=dst_mac,
            src_ip=arp_pkt.dst_ip,
            dst_mac=eth.src,
            dst_ip=arp_pkt.src_ip
        ))
        arp_reply.serialize()

        # Send ARP reply to the appropriate port
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=arp_reply.data
        )
        datapath.send_msg(out)
        self.logger.info(f"ARP reply sent: src_ip={arp_pkt.dst_ip}, src_mac={dst_mac}")

    def handle_arp_reply(self, datapath, arp_pkt):
        """Update ARP table upon receiving an ARP reply."""
        # Add the resolved IP-to-MAC mapping to the ARP table
        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
        self.logger.info(f"ARP table updated with reply: {self.arp_table}")

    def handle_dhcp(self, datapath, in_port, pkt, dhcp_pkt):
        for option in dhcp_pkt.options.option_list:
            if option.tag == 53:  # DHCP Message Type
                if option.value == b'\x01':  # DHCP Discover
                    self.logger.info("DHCP Discover received, sending Offer...")
                    self.handle_dhcp_discover(datapath, in_port, pkt, dhcp_pkt)
                elif option.value == b'\x03':  # DHCP Request
                    self.logger.info("DHCP Request received, sending Ack...")
                    self.handle_dhcp_request(datapath, in_port, pkt, dhcp_pkt)

    def handle_dhcp_discover(self, datapath, in_port, pkt, dhcp_pkt):
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
        assigned_ip = self.assign_ip(dhcp_pkt.chaddr)  # Dynamically assign an IP address
        if assigned_ip:
            self.logger.info(f"DHCP Discover received from {dhcp_pkt.chaddr}. Assigned IP: {assigned_ip}")
            dhcp_offer = self.create_dhcp_offer(eth_pkt, dhcp_pkt, assigned_ip)
            self.logger.info(f"Sending DHCP Offer: xid={dhcp_pkt.xid}, ip={assigned_ip}")
            self.send_dhcp_packet(datapath, in_port, dhcp_offer)
            self.install_ip_flow(datapath, assigned_ip, self.dhcp_server_ip, in_port, datapath.ofproto.OFPP_CONTROLLER)
        else:
            self.logger.error(f"Unable to assign IP for {dhcp_pkt.chaddr}. No available IPs.")

    def handle_dhcp_request(self, datapath, in_port, pkt, dhcp_pkt):
        self.logger.info(f"DHCP Request received: xid={dhcp_pkt.xid}, chaddr={dhcp_pkt.chaddr}")
        dhcp_ack = self.create_dhcp_ack(dhcp_pkt, datapath, in_port)
        self.logger.info(f"Sending DHCP Ack: xid={dhcp_pkt.xid}, ip={self.dhcp_assigned_ip}")
        self.send_dhcp_packet(datapath, in_port, dhcp_ack)

        # Install flow for the requested IP address (to allow communication between hosts)
        self.install_ip_flow(datapath, self.dhcp_assigned_ip, dhcp_pkt.yiaddr, in_port, datapath.ofproto.OFPP_CONTROLLER)

    def create_dhcp_offer(self, eth_pkt, dhcp_pkt, assigned_ip):
        """Create a DHCP Offer with dynamically assigned IP."""
        offer_pkt = packet.Packet()

        eth_dst = eth_pkt.src
        eth_src = self.dhcp_server_mac

        ip = ipv4.ipv4(src=self.dhcp_server_ip, dst="255.255.255.255", proto=socket.IPPROTO_UDP)
        udp_layer = udp.udp(src_port=67, dst_port=68)

        # Subnet mask option
        subnet_mask = dhcp_option(tag=1, value=b'\xff\xff\xff\x00')  # 255.255.255.0 in binary

        # DHCP offer
        offer_dhcp = dhcp.dhcp(
            op=dhcp.DHCP_OFFER,
            xid=dhcp_pkt.xid,
            chaddr=dhcp_pkt.chaddr,
            yiaddr=assigned_ip,
            siaddr=self.dhcp_server_ip,
            options=dhcp.options([subnet_mask])  # Include subnet mask in options
        )
        offer_pkt.add_protocol(ethernet.ethernet(dst=eth_dst, src=eth_src, ethertype=ether_types.ETH_TYPE_IP))
        offer_pkt.add_protocol(ip)
        offer_pkt.add_protocol(udp_layer)
        offer_pkt.add_protocol(offer_dhcp)

        offer_pkt.serialize()
        return offer_pkt

    def create_dhcp_ack(self, dhcp_pkt, assigned_ip):
        """Create a DHCP Ack packet."""
        ack_pkt = packet.Packet()

        eth_dst = dhcp_pkt.chaddr
        eth_src = self.dhcp_server_mac

        ip = ipv4.ipv4(src=self.dhcp_server_ip, dst="255.255.255.255", proto=socket.IPPROTO_UDP)
        udp_layer = udp.udp(src_port=67, dst_port=68)

        # Subnet mask option
        subnet_mask = dhcp_option(tag=1, value=b'\xff\xff\xff\x00')  # 255.255.255.0 in binary

        # DHCP ack
        ack_dhcp = dhcp.dhcp(
            op=dhcp.DHCP_ACK,
            xid=dhcp_pkt.xid,
            chaddr=dhcp_pkt.chaddr,
            yiaddr=assigned_ip,
            siaddr=self.dhcp_server_ip,
            options=dhcp.options([subnet_mask])  # Include subnet mask in options
        )
        ack_pkt.add_protocol(ethernet.ethernet(dst=eth_dst, src=eth_src, ethertype=ether_types.ETH_TYPE_IP))
        ack_pkt.add_protocol(ip)
        ack_pkt.add_protocol(udp_layer)
        ack_pkt.add_protocol(ack_dhcp)

        ack_pkt.serialize()
        return ack_pkt

    def send_dhcp_packet(self, datapath, in_port, dhcp_pkt):
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=dhcp_pkt.data
        )
        datapath.send_msg(out)

    def install_ip_flow(self, datapath, src_ip, dst_ip, in_port, out_port):
        # Create and install a flow for the IP communication
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 10, match, actions)

    def save_packet_to_pcap(self, pkt):
        """
        Save the received packet to the PCAP file.
        :param pkt: Ryu packet object.
        """
        try:
            scapy_pkt = pkt.data  # Raw packet data from Ryu
            self.pcap_writer.write(scapy_pkt)  # Write to PCAP file
            self.logger.info("Packet written to PCAP file.")
        except Exception as e:
            self.logger.error(f"Failed to write packet to PCAP file: {e}")
