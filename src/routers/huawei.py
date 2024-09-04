import socket
from routers.communication import Communication
from routers.enums import ACL, RouteType


class HuaweiCommunication(Communication):

    def __init__(self, host, port):
        super().__init__(host, port)

    def close(self):
        print("Huawei special close :)")
        # send clean shutdown to tell server that we are done talking
        # just do not do anything after this as a test
        self._connection.get_socket().shutdown(socket.SHUT_WR)
        # self.__connection.close()

    def __interface_cmd(self, command, interface):
        self._send_cmd('system-view')
        self._send_cmd(f'interface {interface}')
        self._send_cmd(command)
        self._send_cmd('commit')
        # exit interface view
        self._send_cmd('quit')
        # exit system view
        self._send_cmd('quit')

    def __general_cmd(self, command):
        self._send_cmd('system-view')
        self._send_cmd(command)
        self._send_cmd('commit')
        self._send_cmd('quit')

    def add_acl(self, acl_type: ACL, interface):
        return
        if acl_type is ACL.DEST_64:
            self.__interface_cmd('', interface)
        elif acl_type is ACL.DEST_48:
            self.__interface_cmd('', interface)
        elif acl_type is ACL.SOURCE_64:
            self.__interface_cmd('', interface)

    def remove_acl(self, acl_type: ACL, interface):
        return
        if acl_type is ACL.DEST_64:
            self.__interface_cmd('', interface)
        elif acl_type is ACL.DEST_48:
            self.__interface_cmd('', interface)
        elif acl_type is ACL.SOURCE_64:
            self.__interface_cmd('', interface)

    def add_route(self, route_type: RouteType, prefix, next_hop):
        prefix_part1, prefix_part2 = prefix.split('/')
        if route_type is RouteType.Static:
            self.__general_cmd(f'ipv6 route-static {prefix_part1} {prefix_part2} {next_hop}')
        elif route_type is RouteType.Null:
            self.__general_cmd(f'ipv6 route-static {prefix_part1} {prefix_part2} NULL 0')

    def remove_route(self, route_type: RouteType, prefix, next_hop):
        prefix_part1, prefix_part2 = prefix.split('/')
        if route_type is RouteType.Static:
            self.__general_cmd(f'undo ipv6 route-static {prefix_part1} {prefix_part2} {next_hop}')
        elif route_type is RouteType.Null:
            self.__general_cmd(f'undo ipv6 route-static {prefix_part1} {prefix_part2} NULL 0')
