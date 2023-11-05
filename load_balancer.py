from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ether_types, ipv4, arp, ethernet
from ryu.lib.mac import haddr_to_int

class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    VIRTUAL_IP = '10.0.0.42' 
    SERVER_PORT = 4
    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.srv_ip = ["10.0.0.4", "10.0.0.5"]
        self.srv_mac = ['00:00:00:00:00:04', '00:00:00:00:00:05']
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet form Host: %s through swithch: %s on port: %s to host: %s" , eth.src, datapath.id, in_port, eth.dst )

        self.mac_to_port[dpid][eth.src] = in_port

        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src )
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 10, match, actions)


        if dpid ==2:
             out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
             datapath.send_msg(out)
        else:
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                arp_header = pkt.get_protocol(arp.arp)

                if arp_header.dst_ip == self.VIRTUAL_IP and arp_header.opcode == arp.ARP_REQUEST:
                    src_ip = self.VIRTUAL_IP
                    src_mac = self.srv_mac[1] if haddr_to_int(arp_header.src_mac) % 2 == 1 else self.srv_mac[0]
                    dst_mac = arp_header.src_mac
                    dst_ip = arp_header.src_ip
                    self.logger.info("Selected server MAC: " + src_mac)
                    reply_packet = packet.Packet()
                    reply_packet.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP))
                    reply_packet.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip,dst_mac=dst_mac, dst_ip=dst_ip))
                    reply_packet.serialize()
                    actionsarp = [parser.OFPActionOutput(in_port)]
                    packet_out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY,data=reply_packet.data, actions=actionsarp, buffer_id=0xffffffff)
                    datapath.send_msg(packet_out)
                    self.logger.info("ARP reply sent")
                    return

            
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip_header = pkt.get_protocol(ipv4.ipv4)
                dst_mac = eth.dst
                src_mac = eth.src
                server_out_port = self.SERVER_PORT
                handled = False
                if ip_header.dst == self.VIRTUAL_IP:
                    if dst_mac == self.srv_mac[0]:
                        server_dst_ip = self.srv_ip[0]
                            
                    else:
                        server_dst_ip = self.srv_ip[1]
                        # Route to server
                    match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ip_proto=ip_header.proto,
                                                ipv4_dst=self.VIRTUAL_IP)

                    actionsip = [parser.OFPActionSetField(ipv4_dst=server_dst_ip),
                                parser.OFPActionOutput(server_out_port)]

                    self.add_flow(datapath, 20, match, actionsip)
                        # Reverse route from server
                    match = parser.OFPMatch(in_port=server_out_port, eth_type=ether_types.ETH_TYPE_IP,
                                                ip_proto=ip_header.proto,
                                                ipv4_src=server_dst_ip,
                                                eth_dst=src_mac)
                    actionsip = [parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
                                parser.OFPActionOutput(in_port)]
                    
                    self.add_flow(datapath, 20, match, actionsip)
                    return
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

