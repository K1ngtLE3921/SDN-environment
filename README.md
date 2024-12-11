# SDN-environment
OS system: Ubuntu 22.04 LTS
Python version: 3.9.21

For DHCP topology:
  Starting mininet to create a virtual network for testing DHCP topology by the following command:

  ### `sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo=single,3 --switch=ovsk --mac`
  
  Running Ryu controller:
  
  ### `ryu-manager topology.py`


For VLAN topology:
  Running custome mininet:

  ### `sudo python vlan_mininet.py`

  Running Ryu controller:

  ### `ryu-manager Vlan.py`

# DAST for SDN
