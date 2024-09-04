import socket
from routers.communication import Communication
from routers.enums import ACL, RouteType


class VyosCommunication(Communication):

    def __init__(self, host, port):
        super().__init__(host, port)

    def __general_cmd(self, command):
        self._send_cmd('configure')
        self._send_cmd(command)
        self._send_cmd('commit')
        self._send_cmd('exit')

    def close(self):
        print("VyOS special close :)")
        # send clean shutdown to tell server that we are done talking
        # just do not do anything after this as a test
        self._connection.get_socket().shutdown(socket.SHUT_WR)
        # self.__connection.close()

    def add_acl(self, acl_type: ACL, interface):
        if acl_type is ACL.DEST_64:
            self.__general_cmd(f'set interfaces ethernet {interface} firewall in ipv6-name dest64')
        elif acl_type is ACL.DEST_48:
            self.__general_cmd(f'set interfaces ethernet {interface} firewall in ipv6-name dest48')
        elif acl_type is ACL.SOURCE_64:
            self.__general_cmd(f'set interfaces ethernet {interface} firewall in ipv6-name src64')

    def remove_acl(self, acl_type: ACL, interface):
        if acl_type is ACL.DEST_64:
            self.__general_cmd(f'delete interfaces ethernet {interface} firewall in ipv6-name dest64')
        elif acl_type is ACL.DEST_48:
            self.__general_cmd(f'delete interfaces ethernet {interface} firewall in ipv6-name dest48')
        elif acl_type is ACL.SOURCE_64:
            self.__general_cmd(f'delete interfaces ethernet {interface} firewall in ipv6-name src64')

    def add_route(self, route_type: RouteType, prefix, next_hop):
        if route_type is RouteType.Static:
            self.__general_cmd(f'set protocols static route6 {prefix} next-hop {next_hop}')
        elif route_type is RouteType.Null:
            self.__general_cmd(f'set protocols static route6 {prefix} blackhole')

    def remove_route(self, route_type: RouteType, prefix, next_hop):
        if route_type is RouteType.Static:
            self.__general_cmd(f'delete protocols static route6 {prefix}')
        elif route_type is RouteType.Null:
            self.__general_cmd(f'delete protocols static route6 {prefix}')
