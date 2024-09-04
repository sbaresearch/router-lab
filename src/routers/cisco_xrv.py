from routers.communication import Communication
from routers.enums import ACL, RouteType


class CiscoXRvCommunication(Communication):

    def __init__(self, host, port):
        super().__init__(host, port)

    def __interface_cmd(self, command, interface):
        self._send_cmd('configure terminal')
        self._send_cmd(f'interface {interface}')
        self._send_cmd(command)
        self._send_cmd('commit')
        self._send_cmd('exit')
        self._send_cmd('exit')

    def __general_cmd(self, command):
        self._send_cmd('configure terminal')
        self._send_cmd(command)
        self._send_cmd('commit')
        self._send_cmd('exit')

    def add_acl(self, acl_type: ACL, interface):
        if acl_type is ACL.DEST_64:
            self.__interface_cmd('ipv6 access-group dest64 ingress', interface)
        elif acl_type is ACL.DEST_48:
            self.__interface_cmd('ipv6 access-group dest48 ingress', interface)
        elif acl_type is ACL.SOURCE_64:
            self.__interface_cmd('ipv6 access-group src64 ingress', interface)

    def remove_acl(self, acl_type: ACL, interface):
        if acl_type is ACL.DEST_64:
            self.__interface_cmd('no ipv6 access-group dest64 ingress', interface)
        elif acl_type is ACL.DEST_48:
            self.__interface_cmd('no ipv6 access-group dest48 ingress', interface)
        elif acl_type is ACL.SOURCE_64:
            self.__interface_cmd('no ipv6 access-group src64 ingress', interface)

    def add_route(self, route_type: RouteType, prefix, next_hop):
        if route_type is RouteType.Static:
            self.__general_cmd(f'router static address-family ipv6 unicast {prefix} {next_hop}')
        elif route_type is RouteType.Null:
            self.__general_cmd(f'router static address-family ipv6 unicast {prefix} Null 0')

    def remove_route(self, route_type: RouteType, prefix, next_hop):
        if route_type is RouteType.Static:
            self.__general_cmd(f'no router static address-family ipv6 unicast {prefix} {next_hop}')
        elif route_type is RouteType.Null:
            self.__general_cmd(f'no router static address-family ipv6 unicast {prefix} Null 0')
