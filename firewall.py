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
        self.add_flow(datapath, 0, match_h2_to_h5, actions)
        self.add_flow(datapath, 0, match_h3_to_h5, actions)
        self.add_flow(datapath, 0, match_h1_to_h4, actions)
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
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        self.logger.info("packet in %s %s %s %s", datapath.id, eth.src, eth.dst, in_port)
        out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    

