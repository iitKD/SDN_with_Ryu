from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types

class LoadBalancerApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancerApp, self).__init__(*args, **kwargs)
        self.virtual_ip = '10.0.0.42'
        self.server_ips = ['10.0.0.4', '10.0.0.5']
        self.server_macs = ['00:00:00:00:00:04', '00:00:00:00:00:05']
        self.server_index = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=self.virtual_ip)
        self.server_index = (self.server_index + 1) % len(self.server_ips)
        actions = [parser.OFPActionSetField(eth_dst=self.server_macs[self.server_index]),
                   parser.OFPActionOutput(2)]  # Forward to port 2 (s2)
        
        self.add_flow(datapath, 10, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

