from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.mac import haddr_to_int
from ryu.lib.packet.ether_types import ETH_TYPE_IP
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
 
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 
    VIRTUAL_IP = '10.0.0.42'
 
    SERVER1_IP = '10.0.0.4'
    SERVER1_MAC = '00:00:00:00:00:04'
    SERVER1_PORT = 4
    SERVER2_IP = '10.0.0.5'
    SERVER2_MAC = '00:00:00:00:00:05'
    SERVER2_PORT = 4
 
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
 
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
 
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
 
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
 
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst_mac = eth.dst
        src_mac = eth.src
 
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
 
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD
 
        actions = [parser.OFPActionOutput(out_port)]
 
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            # verify if we have a valid buffer_id, if yes avoid to send both flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 10, match, actions)
 
        if dpid == 1:
            # Handle ARP Packet
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                arp_header = pkt.get_protocol(arp.arp)
 
                if arp_header.dst_ip == self.VIRTUAL_IP and arp_header.opcode == arp.ARP_REQUEST:
                    # Build an ARP reply packet using source IP and source MAC
                    reply_packet = self.generate_arp_reply(arp_header.src_ip, arp_header.src_mac)
                    actions = [parser.OFPActionOutput(in_port)]
                    packet_out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY, data=reply_packet.data, actions=actions, buffer_id=0xffffffff)
                    datapath.send_msg(packet_out)
                    return
 
            # Handle TCP Packet
            if eth.ethertype == ETH_TYPE_IP:
                ip_header = pkt.get_protocol(ipv4.ipv4)
 
                packet_handled = self.handle_tcp_packet(datapath, in_port, ip_header, parser, dst_mac, src_mac)
                if packet_handled:
                    return
 
            # Send if other packet
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
 
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        else:
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
 
    # Source IP and MAC passed here now become the destination for the reply packet
    def generate_arp_reply(self, dst_ip, dst_mac):
        # Making the load balancer IP as source IP
        src_ip = self.VIRTUAL_IP
 
        src_mac = self.SERVER1_MAC if (haddr_to_int(dst_mac) % 2 == 1) else self.SERVER2_MAC
 
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip))
        pkt.serialize()
        return pkt
 
    def handle_tcp_packet(self, datapath, in_port, ip_header, parser, dst_mac, src_mac):
        packet_handled = False
 
        if ip_header.dst == self.VIRTUAL_IP:
            if dst_mac == self.SERVER1_MAC:
                server_dst_ip = self.SERVER1_IP
                server_out_port = self.SERVER1_PORT
            else:
                server_dst_ip = self.SERVER2_IP
                server_out_port = self.SERVER2_PORT
 
            # Route to server
            match = parser.OFPMatch(in_port=in_port, eth_type=ETH_TYPE_IP, ip_proto=ip_header.proto, ipv4_dst=self.VIRTUAL_IP)
            actions = [parser.OFPActionSetField(ipv4_dst=server_dst_ip), parser.OFPActionOutput(server_out_port)]
            self.add_flow(datapath, 20, match, actions)
            # self.logger.info("<==== Added TCP Flow- Route to Server: " + str(server_dst_ip) + " from Client :" + str(ip_header.src) + " on Switch Port:" + str(server_out_port) + "====>")
 
            match = parser.OFPMatch(in_port=server_out_port, eth_type=ETH_TYPE_IP, ip_proto=ip_header.proto, ipv4_src=server_dst_ip, eth_dst=src_mac)
            actions = [parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP), parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, 20, match, actions)
            # self.logger.info("<==== Added TCP Flow- Reverse route from Server: " + str(server_dst_ip) + " to Client: " + str(src_mac) + " on Switch Port:" + str(in_port) + "====>")
            packet_handled = True
        return packet_handled