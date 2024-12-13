In this lab, the operation system I am using in here is Ubuntu version 22.04 LTS. The reason I do not use the version 24.04 LTS because the Ryu controller not supports for that version, it only supports from version 22.04 LTS or downward version of 22.04 LTS.


# SDN-environment

For DHCP topology:
  Starting mininet to create a virtual network for testing DHCP topology by the following command:

  ### `sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo=single,3 --switch=ovsk --mac`
  
  Running Ryu controller:
  
  ### `ryu-manager topology.py`


For VLAN topology:
  Running custom mininet:

  ### `sudo python vlan_mininet.py`

  Running Ryu controller:

  ### `ryu-manager Vlan.py`

# DAST for SDN
