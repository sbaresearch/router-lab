from routers.communication import Communication
from routers.enums import ACL, RouteType


class MikrotikCommunication(Communication):

    def __init__(self, host, router_dict):
        super().__init__(host, router_dict)
        self.__version = self.grab_version()

    def grab_version(self):
        self._send_cmd('/system resource print')
        counter = 0
        not_done = True
        version_number = 6

        while not_done:
            try:
                line = self._read_line()

                if "version:" in line:
                    # version: 7.2.3 (stable)
                    # split by spaces, grab middle piece
                    version_number = line.split(' ')
                    # convert first character to int for major version number
                    version_number = int(version_number[1][0])

                if line == '':
                    counter += 1
                else:
                    counter = 0
            except EOFError:
                not_done = False

            if counter == 3:
                not_done = False

        return version_number

    def add_acl(self, acl_type: ACL, interface):
        base_acl = f"/ipv6 firewall filter add action=reject chain=forward disabled=no in-interface={interface}"

        if acl_type is ACL.DEST_64:
            self._send_cmd(f'{base_acl} dst-address=2001:db8:{self._private_range:0x}:1::/64 comment=DEST64')
        elif acl_type is ACL.DEST_48:
            self._send_cmd(f'{base_acl} dst-address=2001:db8:{self._private_range:0x}::/48 comment=DEST48')
        elif acl_type is ACL.SOURCE_64:
            self._send_cmd(f'{base_acl} src-address=2001:db8:a000:a::/64 comment=SRC64')

    def remove_acl(self, acl_type: ACL, interface):
        if acl_type is ACL.DEST_64:
            self._send_cmd('/ipv6 firewall filter remove numbers=[find comment="DEST64"]')
        elif acl_type is ACL.DEST_48:
            self._send_cmd('/ipv6 firewall filter remove numbers=[find comment="DEST48"]')
        elif acl_type is ACL.SOURCE_64:
            self._send_cmd('/ipv6 firewall filter remove numbers=[find comment="SRC64"]')

    def add_route(self, route_type: RouteType, prefix, next_hop):

        if route_type is RouteType.Static:
            self._send_cmd(f'/ipv6 route add dst-address={prefix} gateway={next_hop}')
        elif route_type is RouteType.Null and self.__version > 6:
            self._send_cmd(f'/ipv6 route add blackhole dst-address={prefix}')
        elif route_type is RouteType.Null and self.__version <= 6:
            self._send_cmd(f'/ipv6 route add dst-address={prefix} type=unreachable')

    def remove_route(self, route_type: RouteType, prefix, next_hop):
        #  /ipv6 route remove [/ipv6 route find where dst-address=3001::/64 and type=unreachable]
        if route_type is RouteType.Static:
            self._send_cmd(f'/ipv6 route remove [/ipv6 route find where dst-address={prefix} and gateway={next_hop}]')
        elif route_type is RouteType.Null and self.__version > 6:
            self._send_cmd(f'/ipv6 route remove [/ipv6 route find where dst-address={prefix} and blackhole]')
        elif route_type is RouteType.Null and self.__version <= 6:
            self._send_cmd(f'/ipv6 route remove [/ipv6 route find where dst-address={prefix} and type=unreachable]')
