# squidwizard
Squidwizard creates a Squid configuration file (squid.conf) with random IPs in multiple IPv6 subnets 
(e.g. /64) within a larger IPv6 network (e.g. /56).

The configuration file was created based on the introduction from Metahackers.pro:
https://www.metahackers.pro/setup-high-anonymous-elite-proxy/

Also an Ansible file exists (addons/ansible_squid.yaml) to automatically build the proxy in an Ubuntu 18.04 LTS
VPS instance. Reason is that Squid only supports 128 outgoing proxy ports without building it from source and the
CXXFLAGS "DMAXTCPLISTENPORTS=xxx"

Reason for this project was that I searched for a simple way to create a squid.conf file with above 1k
outgoing IPv6 addresses within a larger IPv6 network provided by my VPS hosting provider.

## Squidwizard usage
usage: squidwizard.py [-h] 
    --network NETWORK 
    --interface INTERFACE 
    --source SOURCE 
    [--target-subnet TARGET_SUBNET]

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
        machine.testdomain.ch:
          ansible_user: root
          ansible_python_interpreter: /usr/bin/python3
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
 
## Improvements
Improvements of the code are highly appreciated. Please create a pull request.
 