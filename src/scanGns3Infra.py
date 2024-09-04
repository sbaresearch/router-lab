import json
import pathlib
import time
import argparse
import signal
import sys

from datetime import datetime
from routers import routerTelnet
from routers.communication import Communication
from routers.enums import ACL, RouteType, ScanProtocol

from scapy.sendrecv import AsyncSniffer, sendp
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.volatile import RandShort

from util.helpers import setup_logger

max_router = 15
send_hop_limit = 64
net64 = '2001:db8:{}:3::/64'
net48 = '2001:db8:{}::/48'
default = '::/0'
#####


class ScanInfrastructure:
    def __init__(self):
        self.__log = setup_logger("RoutingLab")
        self.__prefix = '2001:db8:'
        self.__interface = 'tap0'
        self.__results = {'title': ['software', 'target']}
        self.__source_port = RandShort()._fix()
        self.__udp_destination_port = 33434
        self.__tcp_destination_port = 80
        self.__time_map_received = {}
        self.__time_map_sent = {}
        self.__packets = []
        self.__gateway = None
        self.__loop_ttl = 64
        self.__ttl = 64

        self.__parse_args()
        self.__prepare_filter()
        self.__build_infra()
        self.__build_targets()
        if not self.__show_targets:
            self.__build_telnet()

    @staticmethod
    def create_message(p_target, p_hlim=send_hop_limit, p_type=-1, p_code=-1, rtt=-1):
        p_target = p_target.replace('2001:db8', '')
        return f'{p_target :>17} / {p_hlim :>3} / {p_type :>3} / {p_code :>2} / {rtt :>6.3f}'

    @staticmethod
    def print_time_usage(start):
        difference = time.perf_counter_ns() - start
        print(f"[*] Took {difference / 1000000000 :.2f} s")

    @staticmethod
    def json_print(items):
        print(json.dumps(items, indent=4))

    @staticmethod
    def get_flat(infrastructure):
        ips = []
        for router, inner in infrastructure.items():
            ips.append(router)

            for key, value in inner.items():
                if key not in ['software']:
                    ips.extend(value)

        return ips

    def __parse_args(self):
        parser = argparse.ArgumentParser(description='Scan given list')
        parser.add_argument('-c', '--configuration', required=True, type=str, help='Path to configuration file')
        parser.add_argument('-1', '--skip_one', action='store_true', help='Skip first stage', default=False)
        parser.add_argument('-2', '--skip_two', action='store_true', help='Skip second stage', default=False)
        parser.add_argument('-3', '--skip_three', action='store_true', help='Skip third stage', default=False)
        parser.add_argument('-4', '--skip_four', action='store_true', help='Skip fourth stage', default=False)
        parser.add_argument('-5', '--skip_five', action='store_true', help='Skip fifth stage', default=False)
        parser.add_argument('-p', '--print', action='store_true', help='Enable printing', default=False)
        parser.add_argument('-t', '--timeout', type=int, help='Timeout to wait for packets (5s default)', default=5)
        parser.add_argument('-z', '--conf_time', type=int,
                            help='Timeout to wait configuration changes (5s default)', default=5)
        parser.add_argument('--auto', action='store_true', help='Skip printing', default=False)
        parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output', default=False)
        parser.add_argument('-m', '--show_targets', action='store_true', help='Show Targets and exit', default=False)
        parser.add_argument('-i', '--interface', type=str, default='tap0', help='Interface to use for probing')
        parser.add_argument('-x', '--ttl-loops', type=int, default=64, help='Override the sent ttl for case 8')
        parser.add_argument('-g', '--gateway', type=str, default='2001:db8:b000:b::1',
                            help='IPv6 address of the gateway router')

        protocol_group = parser.add_mutually_exclusive_group()
        protocol_group.add_argument('-U', '--udp', action='store_true', default=False)
        protocol_group.add_argument('-T', '--tcp', action='store_true', default=False)
        protocol_group.add_argument('-I', '--icmp', action='store_true', default=True)

        args = parser.parse_args()

        configuration_file = pathlib.Path(args.configuration)
        if not configuration_file.exists() or configuration_file.is_dir():
            self.__log.error("Configuration file doesn't exist or is directory!")
            exit(5)

        self.__configuration = routerTelnet.load_configuration(configuration_file)
        output_dir = pathlib.Path(self.__configuration['settings']['output_directory'])

        if output_dir.exists() and output_dir.is_file():
            print(f"Given output directory at {output_dir} is file!")
            exit(4)

        if not output_dir.exists():
            output_dir.mkdir(parents=True)
            print(f"Created output directory at {output_dir}")

        output_dir = output_dir.expanduser()
        output_dir = output_dir.absolute()
        self.__configuration['settings']['output_directory'] = output_dir

        self.__timeout = args.timeout
        self.__skip_1 = args.skip_one
        self.__skip_2 = args.skip_two
        self.__skip_3 = args.skip_three
        self.__skip_4 = args.skip_four
        self.__skip_5 = args.skip_five
        self.__enable_print = args.print
        self.__auto = args.auto
        self.__verbose = args.verbose
        self.__config_wait_time = args.conf_time
        self.__show_targets = args.show_targets
        self.__interface = args.interface
        self.__gateway = args.gateway
        self.__loop_ttl = args.ttl_loops

        if args.tcp:
            self.__scan_protocol = ScanProtocol.TCP
        elif args.udp:
            self.__scan_protocol = ScanProtocol.UDP
        else:
            self.__scan_protocol = ScanProtocol.ICMP

    def __build_infra(self):
        self.__infrastructure = {}

        for router_dict in self.__configuration['routers']:
            router_name = router_dict['name']

            router_disabled = router_dict.get('disabled', False)
            if router_disabled:
                continue

            if 'display_name' in router_dict:
                router_name = router_dict['display_name']

            # grab the private range of the router
            private_range = int(router_dict['private_range'], 16)
            # add 0x1000 to it, as we have defined
            wan_address = 0x1000 + private_range

            router = f'{self.__prefix}b000:b::{wan_address:0x}'
            inner_interfaces = []
            hosts = []

            for network in ['1', '2']:
                inner_interfaces.append(f'{self.__prefix}{private_range:0x}:{network}::1001')

            for suffix in ['1::1', '1::2', '2::1', '2::2', '3::1']:
                hosts.append(f'{self.__prefix}{private_range:0x}:{suffix}')

            self.__infrastructure[router] = {
                'inner': inner_interfaces,
                'hosts': hosts,
                'software': router_name
            }
        # print(self.__infrastructure)

    def __build_targets(self):
        # get flat list from the previously created infrastructure
        infrastructure_list = self.get_flat(self.__infrastructure)
        # add the non-existing host within the router network
        infrastructure_list.append(f'2001:db8:ffff::6666')

        # ADDED TO ACTUAL ROUTER SO ITS NICELY ORDERED IN THE PRINT
        # add the hosts within the non-existing network but still routed to the routers
        # for i in range(2, max_router):
        #     infrastructure_list.append(f'2001:db8:{str(i) * 4}:cccc::1')
        # add hosts within the correctly routed networks that don't actually exist
        # for i in range(2, max_router):
        #     for suffix in ['aaaa::666', 'bbbb::666']:
        #         infrastructure_list.append(f'{self.__prefix}{str(i) * 4}:{suffix}')

        self.__targets = infrastructure_list
        # print(self.__targets)

        for item in self.__targets:
            self.__results[item] = []

    def __build_telnet(self):
        routers = self.__configuration['routers']
        telnet_host = self.__configuration['settings']['telnet_host']
        for router_id, router_dict in enumerate(routers):
            router_disabled = router_dict.get('disabled', False)

            if router_disabled:
                print(f'Skipping {router_dict["name"]} as disabled')
                continue

            router_communication = routerTelnet.create_router(router_dict, telnet_host)
            if router_communication is None:
                print("Got None for communication!")
                exit(1)

            router_dict['connection'] = router_communication

    def __print_targets(self):
        for item in self.__targets:
            print(item)

    def __reset_tcp(self, packet):
        """
        Resets incoming TCP SYN/ACK packets, this is done by responding with a RST packet.
        We need this as we might scan with TCP SYN Packets
        :param packet: incoming packet
        """
        v6 = False

        if IP in packet:
            ip_packet = packet[IP]
        elif IPv6 in packet:
            v6 = True
            ip_packet = packet[IPv6]
        else:
            return

        # add received time to hashmap
        self.__time_map_received[packet.payload.hashret()] = time.time()

        if TCP in ip_packet and ip_packet.src in self.__targets:
            tcp_packet = ip_packet[TCP]

            if self.__verbose:
                print(f'[*] TCP from {ip_packet.src} : {tcp_packet.sport}')

            if tcp_packet.flags.R:
                if self.__verbose:
                    print("[*] Received reset, ignoring packet")
            elif tcp_packet.flags.S and tcp_packet.flags.A:
                if self.__verbose:
                    print("[*] Received SYN ACK, sending reset!")
                reply_packet = Ether()
                if not v6:
                    reply_packet /= IP(dst=ip_packet.src)
                else:
                    reply_packet /= IPv6(dst=ip_packet.src)
                reply_packet /= TCP(dport=tcp_packet.sport, sport=tcp_packet.dport,
                                    seq=tcp_packet.ack + 1, ack=0, flags='R')
                sendp(reply_packet, verbose=False, iface=self.__interface)

    def __handle_ipv6(self, ip_packet):
        rtt = -1
        message_response = ''
        responder = ip_packet["IPv6"].src
        payload = ip_packet.payload
        hop_limit = ip_packet.hlim
        packet_hash = ip_packet.hashret()

        received_time = self.__time_map_received[packet_hash]

        if ip_packet.src in self.__targets:
            # easy mode, we can read the time
            _packet, time_sent = self.__time_map_sent[ip_packet.src]
            rtt = received_time - time_sent

        # ignore neighbor packets
        if ICMPv6ND_NS in ip_packet or ICMPv6ND_NA in ip_packet:
            if self.__verbose:
                print(f'[-] Skipped Neighbour Discovery message from {responder}')
            return None

        # react to echo replies
        if ip_packet.src in self.__targets and ICMPv6EchoReply in ip_packet:
            icmp_code = payload.code
            icmp_type = payload.type
            message_target = responder
            message_response += self.create_message(responder, hop_limit, icmp_type, icmp_code, rtt)

        elif ip_packet.src in self.__targets and UDP in ip_packet and \
                payload.sport == self.__udp_destination_port and payload.dport == self.__source_port:

            message_target = responder
            message_response += self.create_message(responder, hop_limit, 'UDP', 0, rtt)
        elif ip_packet.src in self.__targets and TCP in ip_packet and \
                payload.sport == self.__tcp_destination_port and payload.dport == self.__source_port:

            if payload.flags.R:
                flag = 'R'
            elif payload.flags.S and payload.flags.A:
                flag = 'SA'
            else:
                flag = '?'

            message_target = responder
            message_response += self.create_message(responder, hop_limit, 'TCP', flag, rtt)
        else:
            # Probably ICMPv6 Error Messages
            icmp_code = payload.code
            icmp_type = payload.type
            # payload is some ICMPv6Error, so we need to get the payload of this error
            # to get the actual IPv6 target address
            if payload.payload is not None:
                message_target = payload.payload.dst
                # grab rtt from icmp error
                _packet, time_sent = self.__time_map_sent[message_target]
                rtt = received_time - time_sent
            else:
                print(f"[!] No Payload in suspected ICMPv6Error message!")
                print(f"[!] Message type: {type(payload).__name__} from {responder}")
                return None

            message_response += self.create_message(responder, hop_limit, icmp_type, icmp_code, rtt)

        return message_target, message_response

    def __prepare_filter(self):
        # use scapy to get own IPs with valid route to the GNS3 networks first hop
        # create a bpf filter to only get ipv6 packets to this node
        self.__own_ipv6 = IPv6(dst=self.__gateway).src
        self.__bpf_filter = f"(ip6 and dst {self.__own_ipv6})"

    def __merge_results(self, results):
        for target, result in results.items():
            if target is None or target == '':
                continue
            self.__results[target].append(result)

    def __create_packet(self):
        if self.__scan_protocol is ScanProtocol.ICMP:
            return ICMPv6EchoRequest(seq=0, id=RandShort())
        elif self.__scan_protocol is ScanProtocol.TCP:
            return TCP(dport=self.__tcp_destination_port, sport=self.__source_port, seq=RandShort(), flags='S')
        elif self.__scan_protocol is ScanProtocol.UDP:
            return UDP(dport=self.__udp_destination_port, sport=self.__source_port)

    def ping_list(self, title, hop_limit=send_hop_limit):
        self.__time_map_received.clear()
        start = time.perf_counter_ns()

        sniffer = AsyncSniffer(
            iface=self.__interface, filter=self.__bpf_filter,
            prn=(lambda pkt: self.__reset_tcp(pkt))  # callback for each packet at the time when it arrives
        )
        sniffer.start()
        time.sleep(.5)

        ping_results = {'title': f'{title :>43}'}
        for ip in self.__targets:
            packet = Ether()
            packet /= IPv6(src=self.__own_ipv6, dst=ip, hlim=hop_limit)
            packet /= self.__create_packet()
            packet /= 'this is a testmessage'
            self.__packets.append((packet, time.time()))
            self.__time_map_sent[ip] = (packet, time.time())
            sendp(packet, verbose=False, iface=self.__interface)
            time.sleep(.3)
        time.sleep(self.__timeout)
        sniffer.stop()
        sniffer_results = sniffer.results
        print(f"[*] Received {len(sniffer_results)} packets")

        for response in sniffer_results:
            # print(response)
            if IPv6 in response:
                ping_response = self.__handle_ipv6(response[IPv6])
                # print(ping_response)

                # Unpack if we got an actual answer
                if ping_response is not None:
                    ping_target, ping_answer = ping_response
                    if ping_target in ping_results:
                        print(f"[!] Got second reply from {ping_target}")
                        print(f"[!] New Answer: {ping_answer}")
                        print(f"[!] First Answer: {ping_answer}")
                    else:
                        ping_results[ping_target] = ping_answer

        # iterate over targets and add timeout message for targets without corresponding response
        for ping_target in self.__targets:
            # print(ping_target)
            if ping_target not in ping_results:
                ping_results[ping_target] = self.create_message('Timeout')
        # print(ping_results)

        self.print_time_usage(start)
        # merge into results dict
        self.__merge_results(ping_results)

    def trace_list(self):
        # prepare results
        trace_results = {'title': []}
        for __item in self.__targets:
            trace_results[__item] = []

        for i in range(1, 4):
            print()
            print(f"[!] Hop Limit: {i}")
            self.ping_list(f"Hop Limit : {str(i)}", hop_limit=i)

    def print_results(self):
        file_list = []

        # prepare title line, remove title item from dict to not make problems later on
        title: list = self.__results.pop('title')
        message = f'{title.pop(0) :25}'
        message += f',{title.pop(0) :25}'
        for item in title:
            message += f',{item}'

        file_list.append(message)
        
        for target, values in self.__results.items():
            router_name = ''

            if target in self.__infrastructure:
                router_name = self.__infrastructure[target]['software']

            # Todo: clean that up somehow?
            # get third word within target address, this represents the private range of the router
            test_target = target.split(':')[2]
            found_private_range = int(test_target, 16)

            # if however the first 13 characters are in line with the gateway, take the last word
            if target[0:12] == self.__gateway[0:12]:
                test_target = target.split(':')[-1]
                found_private_range = int(test_target, 16)

            for router_dict in self.__configuration['routers']:
                if str(found_private_range) == router_dict['private_range']:
                    router_name = router_dict['name']

            message = f'{router_name :25},'
            message += f'{target :25},'
            message += ','.join(values)
            file_list.append(message)

        timestamp = datetime.now().strftime('%Y%m%d%H%M')
        filename = f'{timestamp}_{self.__scan_protocol}_gns3_scan.csv'

        output_dir: pathlib.Path = self.__configuration['settings']['output_directory']
        output_dir = output_dir.joinpath(filename)
        print(f'[*] Storing data to {output_dir}')
        with open(output_dir, 'w+') as print_file:
            for line in file_list:
                print_file.write(line + '\n')
                if self.__enable_print:
                    print(line)

    def __set_acl(self, acl: ACL):
        print(f'[*] Setting ACL {acl} for telnet available routers!')
        for router_dict in self.__configuration['routers']:
            if router_dict.get('disabled', False):
                continue

            if 'connection' in router_dict:
                _connection: Communication = router_dict['connection']
                _connection.add_acl(acl, router_dict['wan'])
                time.sleep(.2)
        time.sleep(.2)

    def __unset_acl(self, acl: ACL):
        print(f'[*] Removing ACL {acl} for telnet available routers!')
        for router_dict in self.__configuration['routers']:
            if router_dict.get('disabled', False):
                continue

            if 'connection' in router_dict:
                _connection: Communication = router_dict['connection']
                _connection.remove_acl(acl, router_dict['wan'])
                time.sleep(.2)
        time.sleep(.2)

    def __set_route(self, route_type: RouteType, prefix, next_hop):
        print(f'[*] Adding route to {prefix} for telnet available routers!')
        # ToDo: figure out how we do that now
        for router_dict in self.__configuration['routers']:
            if router_dict.get('disabled', False):
                continue

            if 'connection' in router_dict:
                _router_prefix = routerTelnet.set_router_range(router_dict, prefix)
                _connection: Communication = router_dict['connection']
                _connection.add_route(route_type, _router_prefix, next_hop)
                time.sleep(.2)
        time.sleep(.2)

    def __unset_route(self, route_type: RouteType, prefix, next_hop):
        print(f'[*] Removing route to {prefix} for telnet available routers!')
        for router_dict in self.__configuration['routers']:
            if router_dict.get('disabled', False):
                continue

            if 'connection' in router_dict:
                _router_prefix = routerTelnet.set_router_range(router_dict, prefix)
                _connection: Communication = router_dict['connection']
                _connection.remove_route(route_type, _router_prefix, next_hop)
            time.sleep(.2)
        time.sleep(.2)

    def __stage1(self):
        if not self.__skip_1:
            print()
            print('***************** CASE 0, 1, 3 *****************')
            print('[*] General Connectivity Test')
            # case 0, check if everything in default is reachable

            # case 1, ping into not routed /48
            # ping 2001:db8:xxxx:cccc::1 where xxxx is router ip times 4
            # Destination Unreachable - No route to destination

            # case 3, ping addresses in correct networks but ip is actually not present
            # Destination Unreachable - Address Unreachable
            if self.__scan_protocol == ScanProtocol.ICMP:
                stage_description = f'ICMP Echo Request'
            else:
                stage_description = f'{self.__scan_protocol} packet'
            self.ping_list(stage_description)

    def __stage2(self):
        if not self.__skip_2:
            print()
            print('***************** CASE 7 *****************')
            print('[*] Hop Limit Exceeded *')

            self.trace_list()

    def __stage3(self):
        if not self.__skip_3:
            print()
            print('***************** CASE 2, 5 *****************')
            print()

            stage = 'Admin prohibited; ACL dest /64'
            current_acl = ACL.DEST_64
            print(f'[*] {stage} *')
            self.__set_acl(current_acl)
            self.__wait_for_conf(stage)
            self.__unset_acl(current_acl)
            print()

            stage = 'Admin prohibited; ACL dest /48'
            print(f'[*] {stage} *')
            current_acl = ACL.DEST_48
            self.__set_acl(current_acl)
            self.__wait_for_conf(stage)
            self.__unset_acl(current_acl)
            print()

            stage = 'Admin prohibited; ACL src /64'
            current_acl = ACL.SOURCE_64
            print(f'[*] {stage} *')
            self.__set_acl(current_acl)
            self.__wait_for_conf(stage)
            self.__unset_acl(current_acl)
            print()

    def __stage4(self):
        if not self.__skip_4:

            print()
            print('***************** CASE 6 *****************')

            stage = 'Null Route single /64'
            print(f'[*] {stage} *')
            self.__set_route(RouteType.Null, net64, None)
            self.__wait_for_conf(stage)
            self.__unset_route(RouteType.Null, net64, None)
            print()

            stage = 'Null Route entire /48'
            print(f'[*] {stage} *')
            self.__set_route(RouteType.Null, net48, None)
            self.__wait_for_conf(stage)
            self.__unset_route(RouteType.Null, net48, None)
            print()

    def __stage5(self):
        if not self.__skip_5:
            print()
            print('***************** CASE 8 *****************')
            print(f'[*] Using TTL of {self.__loop_ttl} for routing loop cases')

            stage = 'Route back single /64'
            print(f'[*] {stage} *')
            self.__set_route(RouteType.Static, net64, self.__gateway)
            self.__wait_for_conf(stage, hop_limit=self.__loop_ttl)
            self.__unset_route(RouteType.Static, net64, self.__gateway)
            print()

            stage = 'Route back entire /48'
            print(f'[*] {stage} *')
            self.__set_route(RouteType.Static, net48, self.__gateway)
            self.__wait_for_conf(stage, hop_limit=self.__loop_ttl)
            self.__unset_route(RouteType.Static, net48, self.__gateway)
            print()

            stage = 'Default route /0'
            print(f'[*] {stage} *')
            self.__set_route(RouteType.Static, default, self.__gateway)
            self.__wait_for_conf(stage, hop_limit=self.__loop_ttl)
            self.__unset_route(RouteType.Static, default, self.__gateway)
            print()

    def __wait_for_conf(self, stage, hop_limit=send_hop_limit):
        if self.__auto:
            print(f'[*] Waiting for config changes to propagate...')
            time.sleep(self.__config_wait_time)
            print(f'[*] Scan started!')
        else:
            input(f'Press Enter to start scan for "{stage}"\n >>')
            print(f'[*] Scan started!')

        self.ping_list(stage, hop_limit=hop_limit)

    def shutdown(self):
        for router_dict in self.__configuration['routers']:
            if 'connection' in router_dict:
                router_dict['connection'].close()

    def main(self):
        print(f"GNS3 Test Infrastructure Scan\n")
        print(f"[*] Using {self.__own_ipv6} as device IP for filter and source")
        print(f"[*] Doing a {self.__scan_protocol} scan!")
        print(f'[*] Packet timeout is {self.__timeout} seconds!')
        print()

        if self.__show_targets:
            self.__print_targets()
            exit(0)

        if self.__auto:
            print("[!] Auto mode enabled!")
            print(f"[!] Waiting {self.__config_wait_time} seconds for each config change!")
            print()

        if self.__skip_1:
            print("[!] Skipping Case 0, 1, 3")
        if self.__skip_2:
            print("[!] Skipping Case 7 (traceroute)")
        if self.__skip_3:
            print("[!] Skipping Case 2, 5")
        if self.__skip_4:
            print("[!] Skipping Case 6")
        if self.__skip_5:
            print("[!] Skipping default route loop")
        print()

        self.__stage1()
        self.__stage2()
        self.__stage3()
        self.__stage4()
        self.__stage5()

        self.print_results()
        self.shutdown()


if __name__ == '__main__':
    scanner = ScanInfrastructure()

    def signal_handler(_sig, _frame):
        print('CTRL+C\'d, lets finish this up')
        scanner.shutdown()

    signal.signal(signal.SIGINT, signal_handler)
    scanner.main()
