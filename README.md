# Squidwizard
Squidwizard creates a Squid and BIND rDNS configuration file (squid.conf) with random IPv6s from multiple IPv6 subnets (e.g. /64) from a larger IPv6 network (e.g. /56).

The Squid configuration file was created based on the introduction from Metahackers.pro:
https://www.metahackers.pro/setup-high-anonymous-elite-proxy/

The rDNS BIND file can be used to create rDNS entries with the following schema:
- IPv6 address with dashes (e.g. fdc1-0072-bb6c-00e3-0000-0000-0000-0001)
- Your domain (e.g. rev.example.com)

Also an Ansible file exists (addons/ansible_squid.yaml) to automatically build the proxy in an Ubuntu 18.04 LTS
VPS instance. Reason is that Squid only supports 128 outgoing proxy ports without building it from source and the
CXXFLAGS "DMAXTCPLISTENPORTS=xxx"

## Squidwizard usage
usage: squidwizard.py [-h] 
    --network NETWORK 
    --interface INTERFACE 
    --source SOURCE 
    [--target-subnet TARGET_SUBNET]
    [--domain DOMAIN]
    [--nameserver NAMESERVER]
    [--config-folder CONFIG_FOLDER]

--network: Add the routed IPv6 network provided by your provider, e.g. fdc1:0072:bb6c:e3::/56
--interface: Define the network interface, e.g. eth0
--source: The IPv4 IP you are accessing the router from, e.g. 1.2.3.4
--target-subnet: Default is a "64". Please provide a different value if you want a different subnet or more/less
random IPs
--domain: Default is "example.com". Please provide your domain for the BIND rDNS configuration
--nameserver: Default is "ns1.example.com". Please provide the nameserver for the BIND rDNS configuration
--config-folder: Default is "config". Create a different subfolder in case you want to change the destination for the configuration files

## Ansible usage
### /etc/ansible/hosts
Create first an entry for your proxy in your /etc/ansible/hosts file. The variables NETWORK, INTERFACE & SOURCE
are needed in order to work

Example:
all:
  hosts:
    localhost
  children:
    squidproxies:
      hosts:
        machine.testdomain.com:
          ansible_user: root
          NETWORK: "fdc1:0072:bb6c:e3::/56"
          INTERFACE: eth0
          SOURCE: 1.2.3.4

### Run ansible-playbook
Run the ansible_squid.yaml file with ansible-playbook:
 
ansible-playbook addons/ansible_squid.yaml

## VPS providers with IPv6 networks
 - Linode (Request via Ticket a /56, multiple locations) - https://www.linode.com/
 - Terrahost (out of the box /56, Norway) - https://terrahost.no/
 - online.net (Request via web interface a /48, France) - https://www.online.net
 - ipv6onlyhosting.com (Request via email) - https://ipv6onlyhosting.com
 
## Improvements
Improvements of the code are highly appreciated. Please create a pull request.
 