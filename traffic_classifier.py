from collections import defaultdict
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import arp, ethernet, icmp, ipv4, packet, tcp, udp
from ryu.ofproto import ether, inet, ofproto_v1_3


class TrafficClassifier(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficClassifier, self).__init__(*args, **kwargs)
        self.stats = {
            "TCP": {"packets": 0, "bytes": 0},
            "UDP": {"packets": 0, "bytes": 0},
            "ICMP": {"packets": 0, "bytes": 0},
            "ARP": {"packets": 0, "bytes": 0},
            "BLOCKED": {"packets": 0, "bytes": 0},
            "OTHER": {"packets": 0, "bytes": 0},
        }
        self.mac_to_port = defaultdict(dict)
        self.datapaths = {}
        self.firewall_rules = [
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.3",
                "protocol": "ICMP",
                "action": "BLOCK",
            }
        ]
        self.monitor_thread = hub.spawn(self._monitor)
        self._print_banner()

    def _print_banner(self):
        print("\n" + "=" * 72)
        print("TRAFFIC CLASSIFICATION SYSTEM INITIALIZED")
        print("=" * 72)
        print("Classification targets: TCP, UDP, ICMP, ARP, OTHER")
        print("Firewall policy:")
        for rule in self.firewall_rules:
            print(
                f"  {rule['action']}: {rule['protocol']} {rule['src_ip']} -> {rule['dst_ip']}"
            )
        print("Explicit OpenFlow rules are installed for protocol capture and blocking.")
        print("=" * 72 + "\n")

    def _monitor(self):
        while True:
            hub.sleep(10)
            for datapath in list(self.datapaths.values()):
                self._request_flow_stats(datapath)
            self._print_stats()

    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _print_stats(self):
        print("\n" + "=" * 72)
        print(f"Traffic Statistics Report - {time.ctime()}")
        print("=" * 72)
        print(f"{'Protocol':<10} {'Packets':<15} {'Bytes':<15}")
        print("-" * 72)
        total_packets = 0
        total_bytes = 0
        for proto, data in self.stats.items():
            print(f"{proto:<10} {data['packets']:<15,} {data['bytes']:<15,}")
            total_packets += data["packets"]
            total_bytes += data["bytes"]
        print("-" * 72)
        print(f"{'TOTAL':<10} {total_packets:<15,} {total_bytes:<15,}")
        if total_packets:
            print("\nTraffic Distribution:")
            for proto in ("TCP", "UDP", "ICMP", "ARP", "BLOCKED", "OTHER"):
                packets = self.stats[proto]["packets"]
                if packets:
                    print(f"  {proto:<8} {(packets / total_packets) * 100:5.1f}%")
        print("=" * 72 + "\n")

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        idle_timeout=0,
        hard_timeout=0,
    ):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = []
        if actions:
            instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions,
                )
            ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    def _install_base_rules(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        controller_action = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]

        self.add_flow(
            datapath,
            300,
            parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ipv4_src="10.0.0.1",
                ipv4_dst="10.0.0.3",
                ip_proto=inet.IPPROTO_ICMP,
            ),
            [],
        )

        self.add_flow(
            datapath,
            200,
            parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP),
            controller_action,
        )
        self.add_flow(
            datapath,
            200,
            parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ip_proto=inet.IPPROTO_TCP,
            ),
            controller_action,
        )
        self.add_flow(
            datapath,
            200,
            parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ip_proto=inet.IPPROTO_UDP,
            ),
            controller_action,
        )
        self.add_flow(
            datapath,
            200,
            parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ip_proto=inet.IPPROTO_ICMP,
            ),
            controller_action,
        )
        self.add_flow(datapath, 0, parser.OFPMatch(), controller_action)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self._install_base_rules(datapath)
        print(f"Switch s{datapath.id} connected. Base OpenFlow rules installed.")

    def _update_stats(self, protocol, length, blocked=False):
        key = "BLOCKED" if blocked else protocol
        if key not in self.stats:
            key = "OTHER"
        self.stats[key]["packets"] += 1
        self.stats[key]["bytes"] += length

    def _get_protocol_details(self, pkt):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            return "ARP", None, None, None, arp_pkt
        if not ip_pkt:
            return "OTHER", None, None, None, None
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if tcp_pkt:
            return "TCP", ip_pkt, tcp_pkt, None, None
        if udp_pkt:
            return "UDP", ip_pkt, None, udp_pkt, None
        if icmp_pkt:
            return "ICMP", ip_pkt, None, None, None
        return "OTHER", ip_pkt, None, None, None

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst
        self.mac_to_port[datapath.id][src] = in_port

        protocol, ip_pkt, tcp_pkt, udp_pkt, arp_pkt = self._get_protocol_details(pkt)
        self._update_stats(protocol, len(msg.data))

        if arp_pkt:
            print(f"ARP: {arp_pkt.src_ip} -> {arp_pkt.dst_ip}")
        elif ip_pkt:
            details = ""
            if tcp_pkt:
                details = f" src_port={tcp_pkt.src_port} dst_port={tcp_pkt.dst_port}"
            elif udp_pkt:
                details = f" src_port={udp_pkt.src_port} dst_port={udp_pkt.dst_port}"
            print(f"{protocol}: {ip_pkt.src} -> {ip_pkt.dst}{details}")
        else:
            print(f"OTHER: {src} -> {dst}")

        if dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][dst]
            actions = [parser.OFPActionOutput(out_port)]
            if ip_pkt and protocol in {"TCP", "UDP", "ICMP"}:
                self._install_unicast_flow(
                    datapath,
                    in_port,
                    src,
                    dst,
                    out_port,
                    protocol,
                    ip_pkt,
                    tcp_pkt,
                    udp_pkt,
                )
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def _install_unicast_flow(
        self,
        datapath,
        in_port,
        src_mac,
        dst_mac,
        out_port,
        protocol,
        ip_pkt,
        tcp_pkt,
        udp_pkt,
    ):
        parser = datapath.ofproto_parser
        match_fields = {
            "in_port": in_port,
            "eth_src": src_mac,
            "eth_dst": dst_mac,
            "eth_type": ether.ETH_TYPE_IP,
            "ipv4_src": ip_pkt.src,
            "ipv4_dst": ip_pkt.dst,
        }

        if protocol == "TCP":
            match_fields["ip_proto"] = inet.IPPROTO_TCP
            match_fields["tcp_src"] = tcp_pkt.src_port
            match_fields["tcp_dst"] = tcp_pkt.dst_port
        elif protocol == "UDP":
            match_fields["ip_proto"] = inet.IPPROTO_UDP
            match_fields["udp_src"] = udp_pkt.src_port
            match_fields["udp_dst"] = udp_pkt.dst_port
        elif protocol == "ICMP":
            match_fields["ip_proto"] = inet.IPPROTO_ICMP

        self.add_flow(
            datapath,
            250,
            parser.OFPMatch(**match_fields),
            [parser.OFPActionOutput(out_port)],
            idle_timeout=20,
            hard_timeout=60,
        )

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        interesting = []
        for stat in body:
            if stat.priority >= 200:
                interesting.append(
                    {
                        "priority": stat.priority,
                        "packets": stat.packet_count,
                        "bytes": stat.byte_count,
                        "match": stat.match,
                    }
                )

        if interesting:
            print("Installed flow summary:")
            for entry in interesting[:10]:
                print(
                    f"  priority={entry['priority']} packets={entry['packets']} "
                    f"bytes={entry['bytes']} match={entry['match']}"
                )
