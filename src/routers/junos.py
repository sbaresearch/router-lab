from routers.communication import Communication
from routers.enums import ACL, RouteType


class JunosCommunication(Communication):

    def __init__(self, host, port):
        super().__init__(host, port)

    def __generic_cmd(self, command):
        self._send_cmd('edit')
        self._send_cmd(command)
        self._send_cmd('commit and-quit')

    def add_acl(self, acl_type: ACL, interface):
        if acl_type is ACL.DEST_64:
            self.__generic_cmd(f'set interfaces {interface} unit 0 family inet6 filter input dest64')
        elif acl_type is ACL.DEST_48:
            self.__generic_cmd(f'set interfaces {interface} unit 0 family inet6 filter input dest48')
        elif acl_type is ACL.SOURCE_64:
            self.__generic_cmd(f'set interfaces {interface} unit 0 family inet6 filter input src64')

    def remove_acl(self, acl_type: ACL, interface):
        if acl_type is ACL.DEST_64:
            self.__generic_cmd(f'delete interfaces {interface} unit 0 family inet6 filter input dest64')
        elif acl_type is ACL.DEST_48:
            self.__generic_cmd(f'delete interfaces {interface} unit 0 family inet6 filter input dest48')
        elif acl_type is ACL.SOURCE_64:
            self.__generic_cmd(f'delete interfaces {interface} unit 0 family inet6 filter input src64')

    def add_route(self, route_type: RouteType, prefix, next_hop):
        if route_type is RouteType.Static:
            self.__generic_cmd(f'set routing-options rib inet6.0 static route {prefix} next-hop {next_hop}')
        elif route_type is RouteType.Null:
            self.__generic_cmd(f'set routing-options rib inet6.0 static route {prefix} reject')

    def remove_route(self, route_type: RouteType, prefix, next_hop):
        if route_type is RouteType.Static:
            self.__generic_cmd(f'delete routing-options rib inet6.0 static route {prefix} next-hop {next_hop}')
        elif route_type is RouteType.Null:
            self.__generic_cmd(f'delete routing-options rib inet6.0 static route {prefix} reject')
