from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
#from mininet.link import TCLink
import time
import os

def assignmentTopo():
    net = Mininet( controller=RemoteController)
    ######################################################################################
    ############ CODE SHOULD ONLY BE ADDED BELOW  #################################
    info( '*** Adding controller\n' )
     # =>add the controller here

    info( '*** Adding hosts\n' )
    h1 = net.addHost( 'h1', ip='10.0.0.1', mac='00:00:00:00:00:01' )
    # =>h1 is already added, now add the other hosts here

    info( '*** Adding switches\n' )
    # =>add the switches here's2' )

    info( '*** Creating links\n' )
    # =>create the links here


    info( '*** Starting network\n')
    net.start()
    h1, h2, h3, h4 = net.hosts[0],net.hosts[1],net.hosts[2],net.hosts[3]

    # =>fill in here command to add two queues to the correct port of the correct switch: Q0 with min rate 20000000 and max rate -SELECT THE PROPER RATE-, Q1 with min rate 50000000 and max rate -SELECT THE PROPER RATE-

    # =>fill in here command to add one queue to the correct port of the correct switch: Q0 with min rate 20000000 and max rate -SELECT THE PROPER RATE-
   
    # =>fill in here command to add two queues to the correct port of the correct switch: you decide number of queues and rates



    ########### THIS IS THE END OF THE AREA WHERE YOU NEED TO ADD CODE ##################################
    #####################################################################################################
    # Don't modify the code below, these will test your controller
    h1.cmd('sudo sysctl -w net.ipv4.tcp_syn_retries=1')
    h1.cmd('sudo sysctl -w net.ipv4.tcp_retries=1')
    h2.cmd('sudo sysctl -w net.ipv4.tcp_syn_retries=1')
    h2.cmd('sudo sysctl -w net.ipv4.tcp_retries=1')
    h3.cmd('sudo sysctl -w net.ipv4.tcp_syn_retries=1')
    h3.cmd('sudo sysctl -w net.ipv4.tcp_retries=1')
    h4.cmd('sudo sysctl -w net.ipv4.tcp_syn_retries=1')
    h4.cmd('sudo sysctl -w net.ipv4.tcp_retries=1')


    info( '\n\n\n\n*** Testing CIR from H1 to H3 port 40 - should be capped at 30Mb/s\n')
    h3.cmd('iperf -s -p40 &')
    print(h1.cmd('iperf -c %s -p40' % h3.IP()))
    time.sleep(3)
    
    info( '\n\n\n\n*** Testing CIR from H1 to H2 port 60 - should be capped at 150Mb/s\n')
    h2.cmd('iperf -s -p60 &')
    print(h1.cmd('iperf -c %s -p60' % h2.IP()))
    time.sleep(3)
    
    info( '\n\n\n\n*** Testing CIR from H1 to H4 - should not be capped\n')
    h4.cmd('iperf -s &')
    print(h1.cmd('iperf -c %s' % h4.IP()))
    time.sleep(3)

    info( '\n\n\n\n*** Testing CIR from H2 to H4 - should be capped at 200Mb/s\n')
    print(h2.cmd('iperf -c %s' % h4.IP()))
    time.sleep(3)
    
    info( '\n\n\n\n*** Testing CIR from H4 to H1 - should not be capped\n')
    h1.cmd('iperf -s &')
    print(h4.cmd('iperf -c %s' % h1.IP()))
    time.sleep(3)
    
    info( '\n\n\n\n*** Testing link from H3 to H4 - should be blocked\n')
    print(h3.cmd('iperf -c %s' % h4.IP()))
    time.sleep(3)

    info( '\n\n\n\n*** Testing link from H4 to H2 - should be uncapped\n')
    print(h4.cmd('iperf -c %s -p60' % h2.IP()))
    time.sleep(3)

    info( '\n\n\n\n*** Testing link from H4 to H3 - should be blocked\n')
    print(h4.cmd('iperf -c %s -p40' % h3.IP()))
    time.sleep(1)

    CLI( net )
    os.system('sudo ovs-vsctl clear Port s1-eth1 qos')
    os.system('sudo ovs-vsctl clear Port s1-eth2 qos')
    os.system('sudo ovs-vsctl clear Port s1-eth3 qos')
    os.system('sudo ovs-vsctl clear Port s2-eth1 qos')
    os.system('sudo ovs-vsctl clear Port s2-eth2 qos')
    os.system('sudo ovs-vsctl clear Port s2-eth3 qos')

    os.system('sudo ovs-vsctl --all destroy qos')
    os.system('sudo ovs-vsctl --all destroy queue')
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    assignmentTopo()

