import os
import random
import argparse
import sys
from datetime import datetime
from ipaddress import ip_network, ip_address

import dns.zone
import dns.rdataset
import yaml

START_PORT = 3128
MAX_PREFIX_DISTANCE = 10
IGNORED_NETWORKS = 1


class SquidWizard:
    def __init__(
        self,
        network: str,
        interface: str,
        source: str,
        target_subnet=64,
        domain=None,
        nameservers=None,
        config_folder="config",
    ):
        self.network = network
        self.interface = interface
        self.source = source
        self.target_subnet = target_subnet
        self.domain = domain
        self.nameservers = nameservers
        self.config_folder = config_folder

    def new_prefix_length(self) -> int:
        """
        Returns a target prefix length with maximum 1024 or 10^10 subnets
        """
        network_prefix_length = ip_network(self.network, strict=False).prefixlen
        prefix_distance = self.target_subnet - network_prefix_length
        if prefix_distance <= MAX_PREFIX_DISTANCE:
            return self.target_subnet
        else:
            return network_prefix_length + MAX_PREFIX_DISTANCE

    @staticmethod
    def random_ip_address(subnet: ip_network) -> ip_address:
        """
        Returns a random IP address from the provided subnet
        """
        return subnet[random.randint(1, subnet.num_addresses)]

    def generate_ipv6_addresses(self) -> list:
        """
        Returns a list of random ip adresses from the new prefix less the number of
        ignored networks due to the networkd limitation of max 1024 fix IP adresses
        """
        ipv6_network = ip_network(self.network, strict=False)
        ipv6_subnets = ipv6_network.subnets(new_prefix=self.new_prefix_length())
        return [self.random_ip_address(net) for net in ipv6_subnets][IGNORED_NETWORKS:]

    def write_squid_config(self, ip_list: list) -> None:
        """
        Function writes a squid configuration
        """
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

    def write_netplan_config(self, ip_list: list) -> None:
        """
        Functions writes a secondary netplan configuration
        """
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

    def write_ptr_zone_file(self, ip_list: list) -> None:
        """
        Function writes a BIND configuration file for the reverse DNS entry of the
        network
        """
        zone_origin = self._retrive_zone_origin(self.network)
        zone = dns.zone.Zone(origin=zone_origin)

        if self.nameservers:
            nameservers_list = self.nameservers.split(",")
        else:
            nameservers_list = [f"{prefix}.{self.domain}" for prefix in ["ns1", "ns2"]]
        zone = self._add_to_zone(
            zone,
            "@",
            "SOA",
            f"{nameservers_list[0]}. "  # primary-name-server
            f"hostmaster.{self.domain}. "  # hostmaster-email
            f"{datetime.now().strftime('%Y%m%d%H')} "  # serial-number
            f"1h "  # time-to-refresh
            f"15m "  # time-to-retry
            f"1w "  # time-to-expire
            f"1h",  # minimum-TTL
        )

        for nameserver in nameservers_list:
            zone = self._add_to_zone(zone, "@", "NS", f"{nameserver}.")

        for ip in ip_list:
            zone = self._add_to_zone(
                zone,
                f"{ip.reverse_pointer}.",
                "PTR",
                f"{ip.exploded.replace(':', '-')}.rev.{self.domain}.",
            )

        zone.to_file(f"{self.config_folder}/{zone_origin}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate Squid, BIND and network configuration files for a multi "
        "IPv6 proxy on Ubuntu 18.04"
    )
    parser.add_argument(
        "--network",
        required=True,
        help='IPv6 network for outgoing connections, e.g. "2a03:94e0:1914::/48"',
    )
    parser.add_argument(
        "--interface", required=True, help='IPv6 interface, e.g. "eth0"'
    )
    parser.add_argument(
        "--source",
        required=True,
        help='ACL source IP address or network, e.g. "85.195.242.0/24"',
    )
    parser.add_argument(
        "--target-subnet",
        required=False,
        type=int,
        default=64,
        help="Target subnet prefix capped to 10^10 - 1",
    )
    parser.add_argument(
        "--domain",
        required=False,
        type=str,
        help="Domain name for the BIND configuration, e.g. example.com",
    )
    parser.add_argument(
        "--nameservers",
        required=False,
        type=str,
        help="Nameserver for the BIND configuration seperated by come, e.g."
        "ns1.example.com, ns2.exmample.com. If not provided it will use by defaul "
        "ns1/ns2.domain.com",
    )
    parser.add_argument(
        "--config-folder",
        required=False,
        type=str,
        default="config",
        help="Different location folder",
    )

    return parser.parse_args(sys.argv[1:])


def main():
    args = parse_args()
    sw = SquidWizard(
        network=args.network,
        interface=args.interface,
        source=args.source,
        target_subnet=args.target_subnet,
        domain=args.domain,
        nameservers=args.nameservers,
        config_folder=args.config_folder,
    )
    ip_list = sw.generate_ipv6_addresses()
    sw.write_squid_config(ip_list)
    sw.write_netplan_config(ip_list)
    if sw.domain:
        sw.write_ptr_zone_file(ip_list)


if __name__ == "__main__":
    main()
