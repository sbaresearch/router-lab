from routers.communication import Communication
from routers.enums import ACL, RouteType


class HPECommunication(Communication):

    def __init__(self, host, port):
        super().__init__(host, port)

    def __interface_cmd(self, command, interface):
        self._send_cmd('system-view')
        self._send_cmd(f'interface {interface}')
        self._send_cmd(command)
        self._send_cmd('exit')
        self._send_cmd('exit')

    def __general_cmd(self, command):
        self._send_cmd('system-view')
        self._send_cmd(command)
        self._send_cmd('exit')

    def add_acl(self, acl_type: ACL, interface):
        if acl_type is ACL.DEST_64:
            self.__interface_cmd(f'packet-filter ipv6 name dest64 inbound', interface)
        elif acl_type is ACL.DEST_48:
            self.__interface_cmd(f'packet-filter ipv6 name dest48 inbound', interface)
        elif acl_type is ACL.SOURCE_64:
            self.__interface_cmd(f'packet-filter ipv6 name src64 inbound', interface)

    def remove_acl(self, acl_type: ACL, interface):
        if acl_type is ACL.DEST_64:
            self.__interface_cmd(f'no packet-filter ipv6 name dest64 inbound', interface)
        elif acl_type is ACL.DEST_48:
            self.__interface_cmd(f'no packet-filter ipv6 name dest48 inbound', interface)
        elif acl_type is ACL.SOURCE_64:
            self.__interface_cmd(f'no packet-filter ipv6 name src64 inbound', interface)

    def add_route(self, route_type: RouteType, prefix, next_hop):
        prefix, prefix_length = self._split_prefix(prefix)

        if route_type is RouteType.Static:
            self.__general_cmd(f'ipv6 route-static {prefix} {prefix_length} {next_hop}')
        elif route_type is RouteType.Null:
            self.__general_cmd(f'ipv6 route-static {prefix} {prefix_length} NULL 0')

    def remove_route(self, route_type: RouteType, prefix, next_hop):
        prefix, prefix_length = self._split_prefix(prefix)

        if route_type is RouteType.Static:
            self.__general_cmd(f'no ipv6 route-static {prefix} {prefix_length} {next_hop}')
        elif route_type is RouteType.Null:
            self.__general_cmd(f'no ipv6 route-static {prefix} {prefix_length} NULL 0')
