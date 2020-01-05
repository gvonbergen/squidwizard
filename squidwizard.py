import os
import random
import argparse
import sys
from ipaddress import IPv6Network, IPv4Network

import yaml

START_PORT = 3128

def get_ipv6(args) -> list:
    ipv6_adresses = []
    available_ipv6net = IPv6Network(f"{args.prefix}/{args.subnet}")
    subnets = available_ipv6net.subnets(new_prefix=64)
    for subnet in subnets:
        subnet_length = subnet.num_addresses
        random_ip = random.randint(1, subnet_length)
        ipv6_adresses.append(str(subnet[random_ip]))

    return ipv6_adresses


def write_squid_config(args, ip_list):
    with open('config/squid.conf', 'w') as f:
        f.write('acl myip src {}\n'.format(IPv4Network(args.source)))
        for idx, value in enumerate(ip_list, START_PORT):
            f.write('acl mynet{} myportname {}\n'.format(idx, idx))
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
        headers = ['Authorization', 'Proxy-Authorization', 'Cache-Control', 'Content-Length', 'Content-Type',
                   'Date allow', 'Host allow', 'If-Modified-Since', 'Pragma', 'Accept', 'Accept-Charset',
                   'Accept-Encoding', 'Accept-Language', 'Connection', 'User-Agent', ]
        for header in headers:
            f.write('request_header_access {} allow all\n'.format(header))
        f.write('request_header_access All deny all\n')
        for header in headers:
            f.write('reply_header_access {} allow all\n'.format(header))
        f.write('reply_header_access All deny all\n')


def write_manual_file(args, ip_list):
    with open('config/ubuntucmd.conf', 'w') as f:
        for ip in ip_list:
            f.write('ip -6 addr add {}/64 dev {}\n'.format(ip, args.interface))


def write_netplan_file(args, ip_list):
    netplan = {
        'network': {
            'ethernets': {
                args.interface: {
                    'addresses': ip_list,
                    'dhcp4': 'yes',
                    'dhcp6': 'no'
                }
            },
            'renderer': 'networkd',
            'version': 2
        },
    }
    with open('config/01-netcfg.yaml', 'w') as f:
        yaml.dump(netplan, f)

def write_proxyfile(args, ip_list):
    with open('config/proxies.conf', 'w') as f:
        for idx, ip in enumerate(ip_list, START_PORT):
            f.write('{}:{}\n'.format(args.vpsip, idx))


def parse_args():
    parser = argparse.ArgumentParser(description='Create a Squid Config-File & add IPs to Ubuntu')
    parser.add_argument('--prefix', required=True, help='IPs for outgoing connections, e.g. "2a03:94e0:1914::"')
    parser.add_argument('--subnet', required=True, type=int, help='IP subnet prefix length, e.g. "48" for a /48')
    parser.add_argument('--interface', required=True, help='Outgoing Interface, e.g. "eth0"')
    parser.add_argument('--source', required=True, help='Source IP connecting from, e.g. "85.195.242.0/24"')
    parser.add_argument('--vpsip', required=True, help='IP of VPS, e.g. "1.2.3.4"')

    return parser.parse_args(sys.argv[1:])


def main():
    args = parse_args()
    ip_list = get_ipv6(args)
    os.makedirs('config', exist_ok=True)
    write_squid_config(args, ip_list)
    write_manual_file(args, ip_list)
    write_netplan_file(args, ip_list)
    write_proxyfile(args, ip_list)


if __name__ == '__main__':
    main()
