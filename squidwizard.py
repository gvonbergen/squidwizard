import os
import random
import argparse
import sys
from datetime import datetime
from ipaddress import ip_network

import dns.zone
import dns.rdataset
import yaml

START_PORT = 3128


class SquidWizard:
    def __init__(
        self,
        network: str,
        interface: str,
        source: str,
        domain="example.com",
        nameserver="ns01.example.com",
        target_subnet=64,
        config_folder="config",
    ):
        self.network = network
        self.interface = interface
        self.source = source
        self.domain = domain
        self.nameserver = nameserver
        self.target_subnet = target_subnet
        self.config_folder = config_folder

    def generate_ipv6_addresses(self) -> list:
        ipv6net = ip_network(self.network, strict=False)
        ipv6subnets = ipv6net.subnets(new_prefix=self.target_subnet)
        return [net[random.randint(1, net.num_addresses)] for net in ipv6subnets]

    def write_squid_config(self, ip_list):
        os.makedirs(self.config_folder, exist_ok=True)
        with open(f"{self.config_folder}/squid.conf", "w") as f:
            f.write(f"acl myip src {self.source}\n")
            for idx, value in enumerate(ip_list, START_PORT):
                f.write(f"acl mynet{idx} myportname {idx}\n")
            f.write("acl SSL_ports port 443\n")
            f.write("acl Safe_ports port 80\n")
            f.write("acl Safe_ports port 443\n")
            f.write("acl CONNECT method CONNECT\n")
            f.write("http_access allow myip\n")
            f.write("http_access deny !Safe_ports\n")
            f.write("http_access deny CONNECT !SSL_ports\n")
            f.write("http_access deny all\n")
            for idx, value in enumerate(ip_list, START_PORT):
                f.write("http_port {} name={}\n".format(idx, idx))
            for idx, value in enumerate(ip_list, START_PORT):
                f.write("tcp_outgoing_address {} mynet{}\n".format(value, idx))
            request_headers = [
                "Authorization",
                "Proxy-Authorization",
                "Cache-Control",
                "Content-Length",
                "Content-Type",
                "Date",
                "Host",
                "If-Modified-Since",
                "Pragma",
                "Accept",
                "Accept-Charset",
                "Accept-Encoding",
                "Accept-Language",
                "Connection",
                "User-Agent",
            ]
            for header in request_headers:
                f.write("request_header_access {} allow all\n".format(header))
            f.write("request_header_access All deny all\n")
            reply_headers = [
                "Allow",
                "WWW-Authenticate",
                "Proxy-Authenticate",
                "Cache-Control",
                "Content-Encoding",
                "Content-Length",
                "Content-Type",
                "Date",
                "Expires",
                "Last-Modified",
                "Location",
                "Pragma",
                "Content-Language",
                "Retry-After",
                "Title",
                "Content-Disposition",
                "Connection",
            ]
            for header in reply_headers:
                f.write("reply_header_access {} allow all\n".format(header))
            f.write("reply_header_access All deny all\n")

    def write_netplan_config(self, ip_list):
        netplan = {
            "network": {
                "renderer": "networkd",
                "version": 2,
                "ethernets": {
                    self.interface: {
                        "addresses": [f"{ip.compressed}/128" for ip in ip_list]
                    }
                },
            }
        }
        os.makedirs(self.config_folder, exist_ok=True)
        with open(f"{self.config_folder}/60-squid.yaml", "w") as f:
            yaml.dump(netplan, f)

    @staticmethod
    def _add_to_zone(zone, name, rtype, input_data):
        rdtype = dns.rdatatype.from_text(rtype)
        rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, input_data)
        n = zone.get_rdataset(name, rdtype, create=True)
        n.add(rdata, ttl=3600)
        return zone

    @staticmethod
    def _retrive_zone_origin(network):
        network_string, prefix_length = ip_network(network).exploded.split("/")
        network_string = network_string.replace(":", "")
        target_network = network_string[: int(int(prefix_length) / 4)]
        return ".".join(target_network[::-1]) + ".ip6.arpa"

    def write_ptr_zone_file(self, ip_list):
        zone_origin = self._retrive_zone_origin(self.network)
        zone = dns.zone.Zone(origin=zone_origin)

        zone = self._add_to_zone(
            zone,
            "@",
            "SOA",
            f"{self.nameserver}. "  # primary-name-server
            f"admin.{self.domain}. "  # hostmaster-email
            f"{datetime.now().strftime('%Y%m%d%H')} "  # serial-number
            f"1h "  # time-to-refresh
            f"15m "  # time-to-retry
            f"1w "  # time-to-expire
            f"1h",  # minimum-TTL
        )
        zone = self._add_to_zone(zone, "@", "NS", f"{self.nameserver}.")

        for ip in ip_list:
            zone = self._add_to_zone(
                zone,
                f"{ip.reverse_pointer}.",
                "PTR",
                f"{ip.exploded.replace(':', '-')}.rev.{self.domain}.",
            )

        zone.to_file(f"config/{zone_origin}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create a Squid Config-File & add IPs to Ubuntu"
    )
    parser.add_argument(
        "--network",
        required=True,
        help='IPs for outgoing connections, e.g. "2a03:94e0:1914::/48"',
    )
    parser.add_argument(
        "--interface", required=True, help='Outgoing Interface, e.g. "eth0"'
    )
    parser.add_argument(
        "--source",
        required=True,
        help='Source IP connecting from, e.g. "85.195.242.0/24"',
    )
    parser.add_argument(
        "--domain",
        required=False,
        type=str,
        default="example.com",
        help="Define the domain for your reverseDNS, e.g. example.com",
    )
    parser.add_argument(
        "--nameserver",
        required=False,
        type=str,
        default="ns01.example.com",
        help="Define your nameserver, e.g. ns1.example.com",
    )
    parser.add_argument(
        "--target-subnet",
        required=False,
        type=int,
        default=64,
        help="Define target network",
    )

    return parser.parse_args(sys.argv[1:])


def main():
    args = parse_args()
    sw = SquidWizard(
        args.network,
        args.interface,
        args.source,
        args.domain,
        args.nameserver,
        args.target_subnet,
    )
    ip_list = sw.generate_ipv6_addresses()
    sw.write_squid_config(ip_list)
    sw.write_netplan_config(ip_list)
    if sw.domain:
        sw.write_ptr_zone_file(ip_list)


if __name__ == "__main__":
    main()
