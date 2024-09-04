from routers.communication import Communication
from routers.enums import ACL, RouteType
import json


COMMIT = 'uci commit'


class OpenWRTCommunication(Communication):

    def __init__(self, host, port):
        super().__init__(host, port)

    def __firewall_command(self, command):
        self._send_cmd(command)
        self._send_cmd(COMMIT)
        self._send_cmd('fw3 reload')
        self._send_cmd(f'reload_config')

    def __get_new_route_id(self):
        route_id = ''
        do = True
        counter = 0
        while do:
            try:
                line = self._read_line()

                if line == '':
                    counter += 1
                else:
                    counter = 0
                if route_id == '' and line.startswith('cfg'):
                    route_id = line

            except EOFError:
                do = False

            if counter == 3:
                do = False
        return route_id

    def __get_route_id(self, route_type: RouteType, prefix, next_hop):
        not_done = True
        counter = 0

        route6 = {}

        self._send_cmd('uci show network')
        while not_done:
            try:
                line = self._read_line()

                if line.startswith('network.@route6['):
                    split_line = line.split('.')
                    if len(split_line) < 3:
                        continue

                    route_id = split_line[1]
                    route_id = route_id.replace('@route6[', '')
                    route_id = route_id.replace(']', '')

                    option = split_line[2]
                    option = option.split('=')
                    key = option[0]
                    key = key.replace("'", '')
                    value = option[1]
                    value = value.replace("'", '')

                    if route_id not in route6:
                        route6[route_id] = {}
                    route6[route_id][key] = value

                if line == '':
                    counter += 1
                else:
                    counter = 0
            except EOFError:
                not_done = False

            if counter == 3:
                not_done = False

        for route_id, route_obj in route6.items():
            if route_obj.get('target') != prefix:
                continue
            elif route_type is RouteType.Static and route_obj.get('gateway') == next_hop:
                return route_id
            elif route_type is RouteType.Null and route_obj.get('type') == 'unreachable':
                return route_id

        return -1

    def add_acl(self, acl_type: ACL, interface):
        if acl_type is ACL.DEST_64:
            self.__firewall_command(f'uci set firewall.@rule[1].enabled=1')
        elif acl_type is ACL.DEST_48:
            self.__firewall_command(f'uci set firewall.@rule[2].enabled=1')
        elif acl_type is ACL.SOURCE_64:
            self.__firewall_command(f'uci set firewall.@rule[3].enabled=1')

    def remove_acl(self, acl_type: ACL, interface):
        if acl_type is ACL.DEST_64:
            self.__firewall_command(f'uci set firewall.@rule[1].enabled=0')
        elif acl_type is ACL.DEST_48:
            self.__firewall_command(f'uci set firewall.@rule[2].enabled=0')
        elif acl_type is ACL.SOURCE_64:
            self.__firewall_command(f'uci set firewall.@rule[3].enabled=0')

    def add_route(self, route_type: RouteType, prefix, next_hop):
        self._send_cmd('uci add network route6')
        route_id = self.__get_new_route_id()
        self._send_cmd(f"uci set network.{route_id}.target='{prefix}'")
        self._send_cmd(f"uci set network.{route_id}.interface='lan'")

        if route_type is RouteType.Static:
            self._send_cmd(f"uci set network.{route_id}.gateway='{next_hop}'")
        elif route_type is RouteType.Null:
            self._send_cmd(f"uci set network.{route_id}.type='unreachable'")
        self._send_cmd(COMMIT)
        self._send_cmd(f'reload_config')

    def remove_route(self, route_type: RouteType, prefix, next_hop):
        route_id = self.__get_route_id(route_type, prefix, next_hop)
        self._send_cmd(f'uci delete network.@route6[{route_id}]')
        self._send_cmd(COMMIT)
        self._send_cmd(f'reload_config')
