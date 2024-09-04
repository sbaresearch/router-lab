import yaml
from routers import cisco, hpe, mikrotik, openwrt, junos, cisco_xrv, huawei, aruba, arista, vyos
from routers.enums import RouterOs


def load_configuration(path):
    with open(path) as input_file:
        configuration = yaml.safe_load(input_file)

    if 'settings' not in configuration:
        print('settings category not found in configuration file!')
        exit(4)

    settings = configuration['settings']

    # check settings or set defaults
    if 'send_hop_limit' not in settings:
        settings['send_hop_limit'] = 64

    if 'gateway' not in settings:
        settings['gateway'] = '2001:db8:b000:b::1'

    if 'telnet_host' not in settings:
        settings['telnet_host'] = 'localhost'

    if 'output_directory' not in settings:
        print('output_directory not found in settings category!')
        exit(4)

    # check defined routers
    if 'routers' not in configuration:
        print('routers category not found in configuration file!')
        exit(4)

    routers = configuration['routers']
    if len(routers) == 0:
        print('routers category is empty in configuration file!')
        exit(4)

    private_network_set = set()

    for router in routers:
        router_name = router['name']

        for required_item in ['telnet_port', 'type', 'wan', 'private_range']:
            if required_item not in router:
                print(f'Required item "{required_item}" missing for router "{router_name}"')
                exit(1)

        private_range = router['private_range']
        if private_range in private_network_set:
            print(f'[!] Duplicated private_range ({private_range}) detected!')
            exit(4)
        private_network_set.add(private_range)

        router_type = router['type']
        try:
            router['enum_type'] = RouterOs[router_type]
        except KeyError:
            print(f'Type "{router_type}" for router "{router_name}" is unknown!')
            exit(1)

    return {
        'settings': settings,
        'routers': routers
    }


def create_router(router_dict, host):
    router_type: RouterOs = router_dict['enum_type']

    if router_type is RouterOs.IOS:
        return cisco.CiscoCommunication(host, router_dict)
    elif router_type is RouterOs.JUNOS:
        return junos.JunosCommunication(host, router_dict)
    elif router_type is RouterOs.MIKROTIK:
        return mikrotik.MikrotikCommunication(host,router_dict)
    elif router_type is RouterOs.HPE:
        return hpe.HPECommunication(host, router_dict)
    elif router_type is RouterOs.OPENWRT:
        return openwrt.OpenWRTCommunication(host, router_dict)
    elif router_type is RouterOs.XRv:
        return cisco_xrv.CiscoXRvCommunication(host, router_dict)
    elif router_type is RouterOs.HUAWEI:
        return huawei.HuaweiCommunication(host, router_dict)
    elif router_type is RouterOs.ARISTA:
        return arista.AristaCommunication(host, router_dict)
    elif router_type is RouterOs.ARUBA:
        return aruba.ArubaCommunication(host, router_dict)
    elif router_type is RouterOs.VYOS:
        return vyos.VyosCommunication(host, router_dict)


def set_router_range(router: dict, route: str):
    return route.format(router.get('private_range'))
