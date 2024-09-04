import enum


class ACL(enum.Enum):
    DEST_64 = 1
    DEST_48 = 2
    SOURCE_64 = 3


class RouterOs(enum.Enum):
    IOS = 1
    JUNOS = 2
    HPE = 3
    MIKROTIK = 4
    OPENWRT = 5
    XRv = 6
    HUAWEI = 7
    ARUBA = 8
    ARISTA = 9
    VYOS = 10


class RouteType(enum.Enum):
    Static = 1
    Null = 2


class ScanProtocol(enum.Enum):
    ICMP = 1
    TCP = 2
    UDP = 3

    def __str__(self):
        return self.name


if __name__ == '__main__':
    print(ScanProtocol.UDP)
