from ipaddress import IPv6Address

from squidwizard import SquidWizard


def test_ipv6_56to64subnet():
    sw = SquidWizard(network='fdc1:0072:bb6c:e3::/56', interface='eth0', source='192.168.1.1')
    ip_list = sw.generate_ipv6_addresses()
    assert len(ip_list) == 256
    assert isinstance(ip_list[0], IPv6Address)


def test_ipv6_64to80subnet():
    sw = SquidWizard(network='fdb8:c38f:49bf:3505::/64', interface='eth0', source='192.168.1.1')
    ip_list = sw.generate_ipv6_addresses(target_subnet=80)
    assert len(ip_list) == 65536
    assert isinstance(ip_list[0], IPv6Address)


def test_write_squid_config(tmp_path):
    sw = SquidWizard(network='fdb8:c38f:49bf:3505::/64', interface='eth0', source='192.168.1.1', config_folder=tmp_path)
    ip_list = [IPv6Address('fdb8:c38f:49bf:3505::2'), IPv6Address('fdb8:c38f:49bf:3505::5')]
    sw.write_squid_config(ip_list=ip_list)
    assert len(list(tmp_path.iterdir())) == 1


