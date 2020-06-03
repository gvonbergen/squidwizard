from ipaddress import IPv6Address, IPv6Network

import pytest
import yaml

from squidwizard import SquidWizard


@pytest.fixture()
def sw_setup(tmp_path):
    sw = SquidWizard(
        network="fdb4:c38f:49bf:3505::/64",
        interface="eth0",
        source="192.168.1.1",
        config_folder=tmp_path,
    )
    ip_list = [
        IPv6Address("fdb4:c38f:49bf:3505::2"),
        IPv6Address("fdb4:c38f:49bf:3505::5"),
    ]
    return sw, ip_list


def test_calculate_new_prefix_length_default():
    sw = SquidWizard(network="fdc1:7::/48", interface="eth0", source="0.0.0.0")
    calculated_new_prefix = sw.new_prefix_length()
    assert calculated_new_prefix == 58


@pytest.mark.parametrize(
    "input_prefix,default_prefix,new_prefix",
    [(48, 64, 58), (56, 64, 64), (48, 56, 56)],
)
def test_calculate_new_prefix_length(input_prefix, default_prefix, new_prefix):
    sw = SquidWizard(
        network=f"fdc1:7::/{input_prefix}",
        interface="eth0",
        source="0.0.0.0",
        target_subnet=default_prefix,
    )
    calculated_new_prefix = sw.new_prefix_length()
    assert calculated_new_prefix == new_prefix


def test_random_ip_address():
    ipv6_network = IPv6Network("fdc1:0072:bb6c:e3::/56", strict=False)
    ipv6_address = SquidWizard.random_ip_address(ipv6_network)
    ipv6_subnet = IPv6Network(f"{ipv6_address}/128", strict=False)
    assert ipv6_subnet.subnet_of(ipv6_network)


def test_ipv6_56to64subnet():
    sw = SquidWizard(
        network="fdc1:0072:bb6c:e3::/56", interface="eth0", source="192.168.1.1"
    )
    ip_list = sw.generate_ipv6_addresses()
    assert len(ip_list) == 255
    assert isinstance(ip_list[0], IPv6Address)


def test_ipv6_64to80subnet():
    sw = SquidWizard(
        network="fdb8:c38f:49bf:3505::/64",
        interface="eth0",
        target_subnet=80,
        source="192.168.1.1",
    )
    ip_list = sw.generate_ipv6_addresses()
    assert len(ip_list) == 1023
    assert isinstance(ip_list[0], IPv6Address)


def test_write_squid_config(tmp_path):
    sw = SquidWizard(
        network="fdb8:c38f:49bf:3505::/64",
        interface="eth0",
        source="192.168.1.1",
        config_folder=tmp_path,
    )
    ip_list = [
        IPv6Address("fdb8:c38f:49bf:3505::2"),
        IPv6Address("fdb8:c38f:49bf:3505::5"),
    ]
    sw.write_squid_config(ip_list=ip_list)
    assert len(list(tmp_path.iterdir())) == 1
    file = tmp_path.joinpath("squid.conf")
    text = file.read_text()
    assert "acl myip src 192.168.1.1" in text
    assert "acl mynet3129 myportname 3129" in text
    assert "acl mynet3130 myportname 3130" not in text
    assert "tcp_outgoing_address fdb8:c38f:49bf:3505::2 mynet3128" in text
    assert "tcp_outgoing_address fdb8:c38f:49bf:3505::5 mynet3129" in text
    assert "request_header_access If-Modified-Since allow all" in text
    assert "reply_header_access Date allow all" in text


def test_write_netplan_config(tmp_path):
    sw = SquidWizard(
        network="fdb4:c38f:49bf:3505::/64",
        interface="eth0",
        source="192.168.1.1",
        config_folder=tmp_path,
    )
    ip_list = [
        IPv6Address("fdb4:c38f:49bf:3505::2"),
        IPv6Address("fdb4:c38f:49bf:3505::5"),
    ]
    sw.write_netplan_config(ip_list=ip_list)
    assert len(list(tmp_path.iterdir())) == 1
    file = tmp_path.joinpath("60-squid.yaml")
    netplan_file = yaml.load(file.read_text(), Loader=yaml.FullLoader)
    assert len(netplan_file["network"]["ethernets"]["eth0"]["addresses"]) == 2
    assert (
        netplan_file["network"]["ethernets"]["eth0"]["addresses"][0]
        == "fdb4:c38f:49bf:3505::2/128"
    )
    assert (
        netplan_file["network"]["ethernets"]["eth0"]["addresses"][1]
        == "fdb4:c38f:49bf:3505::5/128"
    )
    with pytest.raises(IndexError):
        assert netplan_file["network"]["ethernets"]["eth0"]["addresses"][2]


@pytest.fixture()
def sw_nameserver_default(tmp_path):
    sw = SquidWizard(
        network="fdb4:c38f:49bf:3505::/64",
        interface="eth0",
        source="192.168.1.1",
        domain="example.com",
        config_folder=tmp_path,
    )
    sw.write_ptr_zone_file([IPv6Address("fdb4:c38f:49bf:3505::1")])
    file = tmp_path / "5.0.5.3.f.b.9.4.f.8.3.c.4.b.d.f.ip6.arpa"
    file_content = file.read_text()
    return file_content


def test_write_ptr_zone_file_primary_nameserver(sw_nameserver_default):
    assert "SOA ns1.example.com." in sw_nameserver_default


def test_write_ptr_zone_file_hostmaster(sw_nameserver_default):
    assert "hostmaster.example.com." in sw_nameserver_default


def test_write_ptr_zone_file_ns1(sw_nameserver_default):
    assert "NS ns1.example.com." in sw_nameserver_default


def test_write_ptr_zone_file_ns2(sw_nameserver_default):
    assert "NS ns2.example.com." in sw_nameserver_default


@pytest.fixture()
def sw_nameserver_extra_ns(tmp_path):
    sw = SquidWizard(
        network="fdb4:c38f:49bf:3505::/64",
        interface="eth0",
        source="192.168.1.1",
        domain="example.com",
        nameservers="ns1.example.com,ns2.additional.com,ns3.additional.com",
        config_folder=tmp_path,
    )
    sw.write_ptr_zone_file([IPv6Address("fdb4:c38f:49bf:3505::1")])
    file = tmp_path / "5.0.5.3.f.b.9.4.f.8.3.c.4.b.d.f.ip6.arpa"
    file_content = file.read_text()
    return file_content


def test_write_ptr_zone_file_extra_ns_primary_nameserver(sw_nameserver_extra_ns):
    assert "SOA ns1.example.com." in sw_nameserver_extra_ns


def test_write_ptr_zone_file_extra_ns_hostmaster(sw_nameserver_extra_ns):
    assert "hostmaster.example.com." in sw_nameserver_extra_ns


def test_write_ptr_zone_file_extra_ns_ns1(sw_nameserver_extra_ns):
    assert "NS ns1.example.com." in sw_nameserver_extra_ns


def test_write_ptr_zone_file_extra_ns_not_ns2(sw_nameserver_extra_ns):
    assert "NS ns2.example.com." not in sw_nameserver_extra_ns


def test_write_ptr_zone_file_extra_ns_new_ns2(sw_nameserver_extra_ns):
    assert "NS ns2.additional.com." in sw_nameserver_extra_ns


def test_write_ptr_zone_file_extra_ns_new_ns3(sw_nameserver_extra_ns):
    assert "NS ns3.additional.com." in sw_nameserver_extra_ns
