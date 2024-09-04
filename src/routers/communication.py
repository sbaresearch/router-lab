import socket
import telnetlib
from routers.enums import ACL, RouteType


class Communication:

    def __init__(self, host, router_dict):
        port = router_dict['telnet_port']
        self._private_range = int(router_dict['private_range'], 16)
        self._connection = telnetlib.Telnet(host=host, port=port)

    def close(self):
        # send clean shutdown to tell server that we are done talking
        self._connection.get_socket().shutdown(socket.SHUT_WR)
        # try read rest of data
        try:
            _data = self._connection.read_all()
        finally:
            self._connection.close()

    def _send_cmd(self, command):
        self._connection.write(f'{command}\r\n'.encode('ascii'))

    def _read_until(self, until, timeout=1.0):
        return self._connection.read_until(until.encode('ascii'), timeout=timeout)

    def _read_line(self):
        line = self._read_until('\n', 0.2)
        line = line.decode('ascii')
        line = line.replace('\n', '')
        line = line.strip()
        return line

    @staticmethod
    def _split_prefix(prefix):
        split_prefix = prefix.split('/')
        prefix = split_prefix[0]
        prefix_length = split_prefix[1]
        return prefix, prefix_length

    def add_acl(self, acl_type: ACL, interface):
        raise NotImplementedError

    def remove_acl(self, acl_type: ACL, interface):
        raise NotImplementedError

    def add_route(self, route_type: RouteType, prefix, next_hop):
        raise NotImplementedError

    def remove_route(self, route_type: RouteType, prefix, next_hop):
        raise NotImplementedError
