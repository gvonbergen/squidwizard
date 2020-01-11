from ipaddress import IPv6Address

import pytest
import yaml

from squidwizard import SquidWizard


def test_ipv6_56to64subnet():
    sw = SquidWizard(network='fdc1:0072:bb6c:e3::/56', interface='eth0', source='192.168.1.1')
    ip_list = sw.generate_ipv6_addresses()
    assert len(ip_list) == 256
    assert isinstance(ip_list[0], IPv6Address)


def test_ipv6_64to80subnet():
    sw = SquidWizard(network='fdb8:c38f:49bf:3505::/64', interface='eth0', target_subnet=80, source='192.168.1.1')
    ip_list = sw.generate_ipv6_addresses()
    assert len(ip_list) == 65536
    assert isinstance(ip_list[0], IPv6Address)


def test_write_squid_config(tmp_path):
    sw = SquidWizard(network='fdb8:c38f:49bf:3505::/64', interface='eth0', source='192.168.1.1', config_folder=tmp_path)
    ip_list = [IPv6Address('fdb8:c38f:49bf:3505::2'), IPv6Address('fdb8:c38f:49bf:3505::5')]
    sw.write_squid_config(ip_list=ip_list)
    assert len(list(tmp_path.iterdir())) == 1
    file = tmp_path.joinpath('squid.conf')
    text = file.read_text()
    assert 'acl myip src 192.168.1.1' in text
    assert 'acl mynet3129 myportname 3129' in text
    assert 'acl mynet3130 myportname 3130' not in text
    assert 'tcp_outgoing_address fdb8:c38f:49bf:3505::2 mynet3128' in text
    assert 'tcp_outgoing_address fdb8:c38f:49bf:3505::5 mynet3129' in text
    assert 'request_header_access If-Modified-Since allow all' in text
    assert 'reply_header_access Date allow all' in text


def test_write_netplan_config(tmp_path):
    sw = SquidWizard(network='fdb4:c38f:49bf:3505::/64', interface='eth0', source='192.168.1.1', config_folder=tmp_path)
    ip_list = [IPv6Address('fdb4:c38f:49bf:3505::2'), IPv6Address('fdb4:c38f:49bf:3505::5')]
    sw.write_netplan_config(ip_list=ip_list)
    assert len(list(tmp_path.iterdir())) == 1
    file = tmp_path.joinpath('01-netcfg.yaml')
    netplan_file = yaml.load(file.read_text())
    assert len(netplan_file['network']['ethernets']['eth0']['addresses']) == 2
    assert netplan_file['network']['ethernets']['eth0']['addresses'][0] == 'fdb4:c38f:49bf:3505::2/128'
    assert netplan_file['network']['ethernets']['eth0']['addresses'][1] == 'fdb4:c38f:49bf:3505::5/128'
    with pytest.raises(IndexError):
        assert netplan_file['network']['ethernets']['eth0']['addresses'][2]
