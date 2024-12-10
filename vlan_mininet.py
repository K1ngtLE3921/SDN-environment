from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def vlan_topology():
    net = Mininet(controller=Controller, switch=OVSSwitch)
    
    info("*** Adding Controller\n")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info("*** Adding Switch\n")
    s1 = net.addSwitch('s1')

    info("*** Adding Hosts\n")
    h1 = net.addHost('h1', ip='192.168.10.1/24', mac='00:00:00:00:10:02', defaultRoute='via 192.168.10.254')
    h2 = net.addHost('h2', ip='192.168.10.2/24', mac='00:00:00:00:10:03', defaultRoute='via 192.168.10.254')
    h3 = net.addHost('h3', ip='192.168.20.1/24', mac='00:00:00:00:20:02',defaultRoute='via 192.168.20.254')
    h4 = net.addHost('h4', ip='192.168.20.2/24', mac='00:00:00:00:20:03',defaultRoute='via 192.168.20.254')

    info("*** Adding Links\n")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    info("*** Starting Network\n")
    net.start()

    info("*** Configuring VLANs\n")
    # VLAN configuration on hosts
    h1.cmd('vconfig add h1-eth0 10')
    h1.cmd('ifconfig h1-eth0.10 up')
    h2.cmd('vconfig add h2-eth0 10')
    h2.cmd('ifconfig h2-eth0.10 up')

    h3.cmd('vconfig add h3-eth0 20')
    h3.cmd('ifconfig h3-eth0.20 up')
    h4.cmd('vconfig add h4-eth0 20')
    h4.cmd('ifconfig h4-eth0.20 up')

    # VLAN configuration on OVS switch
    s1.cmd('ovs-vsctl set port s1-eth1 tag=10')
    s1.cmd('ovs-vsctl set port s1-eth2 tag=10')
    s1.cmd('ovs-vsctl set port s1-eth3 tag=20')
    s1.cmd('ovs-vsctl set port s1-eth4 tag=20')

    # Allow both VLAN 10 and VLAN 20 to pass through specific ports
    s1.cmd('ovs-vsctl set port s1-eth1 trunks=10,20')
    s1.cmd('ovs-vsctl set port s1-eth3 trunks=10,20')


    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping Network\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    vlan_topology()