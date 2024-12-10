import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, vlan
from ryu.ofproto import ofproto_v1_3

class VLANSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(VLANSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Default table-miss flow entry to send packets to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Check for VLAN tag
        vlan_header = pkt.get_protocol(vlan.vlan)
        if vlan_header:
            vlan_id = vlan_header.vid
            self.logger.info("VLAN packet received: VLAN ID %s", vlan_id)
            self.handle_vlan_packet(datapath, in_port, pkt, vlan_id, msg)
        else:
            self.handle_non_vlan_packet(datapath, in_port, pkt, msg)

    def handle_vlan_packet(self, datapath, in_port, pkt, vlan_id, msg):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # Learn the source MAC address
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        outer_vlan = None
        inner_vlan = None

        # Check if the packet has a VLAN header
        vlan_headers = pkt.get_protocols(vlan.vlan)

        if vlan_headers:
            # The first VLAN header is the outer VLAN tag
            outer_vlan = vlan_headers[0].vid
            self.logger.info("Outer VLAN packet received: VLAN ID %s", outer_vlan)

            # If there is a second VLAN header, it is the inner VLAN tag
            if len(vlan_headers) > 1:
                inner_vlan = vlan_headers[1].vid
                self.logger.info("Inner VLAN packet received: VLAN ID %s", inner_vlan)

        # Match on the outer VLAN ID
        if outer_vlan:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, vlan_vid=(0x1000 | outer_vlan))
        else:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, vlan_vid=(0x1000 | vlan_id))

        # Add flow entry
        self.add_flow(datapath, 1, match, actions)

        # Log packet flow and Wireshark-like capture
        self.wireshark_packet_capture(pkt, src, dst, in_port, out_port, outer_vlan if outer_vlan else vlan_id)

        # Check if buffer_id is 0xffffffff (NO_BUFFER)
        if msg.buffer_id == 0xffffffff:
            data = pkt.data  # If buffer_id is NO_BUFFER, use the packet data
        else:
            data = None  # If not, don't include packet data in the message

        # Send packet out
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)





    def handle_non_vlan_packet(self, datapath, in_port, pkt, msg):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # Learn the source MAC address
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Match on Ethernet source and destination without VLAN
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        self.add_flow(datapath, 1, match, actions)

        # Log packet flow and Wireshark-like capture
        self.wireshark_packet_capture(pkt, src, dst, in_port, out_port)

        # Check if buffer_id is 0xffffffff (NO_BUFFER)
        if msg.buffer_id == 0xffffffff:
            data = pkt.data  # If buffer_id is NO_BUFFER, use the packet data
        else:
            data = None  # If not, don't include packet data in the message

        # Send packet out
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def wireshark_packet_capture(self, pkt, src, dst, in_port, out_port, vlan_id=None):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Ethernet type to protocol mapping
        ether_type_map = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86dd: "IPv6",
            0x8847: "MPLS",
            0x8848: "MPLS",
            0x8100: "VLAN",
            0x88cc: "LLC",
            0x880b: "PPPoE",
            0x884d: "PPP",
            0x8808: "Ethernet Flow Control",
        }
        
        ethertype = eth_pkt.ethertype
        protocol = ether_type_map.get(ethertype, "Unknown")  # Map ethertype to protocol name, or "Unknown"

        if vlan_id:
            self.logger.info(f"[Wireshark Capture] Timestamp: {timestamp} | "
                             f"VLAN: {vlan_id} | Src: {src} -> Dst: {dst} | "
                             f"In Port: {in_port} | Out Port: {out_port} | "
                             f"Ethernet Type: {hex(ethertype)} ({protocol})")
        else:
            self.logger.info(f"[Wireshark Capture] Timestamp: {timestamp} | "
                             f"Src: {src} -> Dst: {dst} | In Port: {in_port} | "
                             f"Out Port: {out_port} | Ethernet Type: {hex(ethertype)} ({protocol})")