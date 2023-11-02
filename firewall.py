from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.lib import addrconv
from ryu import cfg
from ryu.controller import controller
from ryu.lib import hub
from ryu.topology import api as topo_api

class FirewallMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FirewallMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.packet_count = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Add firewall rules to prevent communication between specific hosts
        match_h2_to_h5 = parser.OFPMatch(
            eth_src='00:00:00:00:00:02',  # H2 MAC address
            eth_dst='00:00:00:00:00:05'   # H3 MAC address
        )
        match_h3_to_h5 = parser.OFPMatch(
            eth_src='00:00:00:00:00:03',  # H2 MAC address
            eth_dst='00:00:00:00:00:05'   # H3 MAC address
        )

        match_h1_to_h4 = parser.OFPMatch(
            eth_src='00:00:00:00:00:01',  # H1 MAC address
            eth_dst='00:00:00:00:00:04'   # H4 MAC address
        )

        actions = []

        # Drop the packets that match the firewall rules
        self.add_flow(datapath, 1, match_h2_to_h5, actions)
        self.add_flow(datapath, 1, match_h3_to_h5, actions)
        self.add_flow(datapath, 1, match_h1_to_h4, actions)
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
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Count packets coming from host H3 on switch S1
        if datapath.id == 1 and eth.src == '00:00:00:00:00:03':
            self.packet_count += 1
            self.logger.info(f"Packet count from H3 on switch S1: {self.packet_count}")

    

