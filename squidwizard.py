import os
import random
import argparse
import sys
from ipaddress import ip_network

import yaml

START_PORT = 3128


class SquidWizard:
    def __init__(self, network: str, interface: str, source: str, target_subnet=64, config_folder='config'):
        self.network = network
        self.interface = interface
        self.source = source
        self.target_subnet = target_subnet
        self.config_folder = config_folder

    def generate_ipv6_addresses(self) -> list:
        ipv6net = ip_network(self.network, strict=False)
        ipv6subnets = ipv6net.subnets(new_prefix=self.target_subnet)
        return [net[random.randint(1, net.num_addresses)] for net in ipv6subnets]

    def write_squid_config(self, ip_list):
        os.makedirs(self.config_folder, exist_ok=True)
        with open(f'{self.config_folder}/squid.conf', 'w') as f:
            f.write(f'acl myip src {self.source}\n')
            for idx, value in enumerate(ip_list, START_PORT):
                f.write(f'acl mynet{idx} myportname {idx}\n')
            f.write('acl SSL_ports port 443\n')
            f.write('acl Safe_ports port 80\n')
            f.write('acl Safe_ports port 443\n')
            f.write('acl CONNECT method CONNECT\n')
            f.write('http_access allow myip\n')
            f.write('http_access deny !Safe_ports\n')
            f.write('http_access deny CONNECT !SSL_ports\n')
            f.write('http_access deny all\n')
            for idx, value in enumerate(ip_list, START_PORT):
                f.write('http_port {} name={}\n'.format(idx, idx))
            for idx, value in enumerate(ip_list, START_PORT):
                f.write('tcp_outgoing_address {} mynet{}\n'.format(value, idx))
            request_headers = ['Authorization', 'Proxy-Authorization', 'Cache-Control', 'Content-Length', 'Content-Type',
                               'Date', 'Host', 'If-Modified-Since', 'Pragma', 'Accept', 'Accept-Charset','Accept-Encoding',
                               'Accept-Language', 'Connection', 'User-Agent', ]
            for header in request_headers:
                f.write('request_header_access {} allow all\n'.format(header))
            f.write('request_header_access All deny all\n')
            reply_headers = ['Allow', 'WWW-Authenticate', 'Proxy-Authenticate', 'Cache-Control', 'Content-Encoding',
                             'Content-Length', 'Content-Type', 'Date', 'Expires', 'Last-Modified', 'Location', 'Pragma',
                             'Content-Language', 'Retry-After', 'Title', 'Content-Disposition', 'Connection']
            for header in reply_headers:
                f.write('reply_header_access {} allow all\n'.format(header))
            f.write('reply_header_access All deny all\n')

    def write_netplan_config(self, ip_list, **kwargs):
        kw = {}
        addresses = [f'{ip}/128' for ip in ip_list]
        if 'ipv4' in kwargs and 'gateway4' in kwargs:
            addresses.append(kwargs['ipv4'])
            kw['gateway4'] = kwargs['gateway4']
        else:
            kw['dhcp4'] = 'yes'
        if 'ipv6' in kwargs and 'gateway6' in kwargs:
            addresses.append(kwargs['ipv6'])
            kw['gateway6'] = kwargs['gateway6']
        else:
            kw['dhcp6'] = 'yes'
        netplan = {
            'network': {
                'renderer': 'networkd',
                'version': 2,
                'ethernets': {
                    self.interface: {
                        'addresses': addresses,
                        'nameservers': {
                            'addresses': ['1.1.1.1']
                        },
                        **kw
                    }
                },
            },
        }
        os.makedirs(self.config_folder, exist_ok=True)
        with open(f'{self.config_folder}/01-netcfg.yaml', 'w') as f:
            yaml.dump(netplan, f)


def parse_args():
    parser = argparse.ArgumentParser(description='Create a Squid Config-File & add IPs to Ubuntu')
    parser.add_argument('--network', required=True, help='IPs for outgoing connections, e.g. "2a03:94e0:1914::/48"')
    parser.add_argument('--interface', required=True, help='Outgoing Interface, e.g. "eth0"')
    parser.add_argument('--source', required=True, help='Source IP connecting from, e.g. "85.195.242.0/24"')
    parser.add_argument('--target-subnet', required=False, type=int, default=64, help='Define target network')
    parser.add_argument('--local-net', required=False, help='Provide details about local network with "ipv4=1.1.1.2 '
                                                            'v4gateway=1.1.1.1"')
    return parser.parse_args(sys.argv[1:])


def main():
    args = parse_args()
    sw = SquidWizard(args.network, args.interface, args.source, args.target_subnet)
    ip_list = sw.generate_ipv6_addresses()
    sw.write_squid_config(ip_list)
    sw.write_netplan_config(ip_list, **dict(arg.split('=') for arg in args.local_net.split(' ')))


if __name__ == '__main__':
    main()
