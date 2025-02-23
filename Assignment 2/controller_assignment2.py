from pox.core import core
import pox.lib.packet as pkt
import pox.lib.packet.ethernet as eth
import pox.lib.packet.arp as arp
import pox.lib.packet.icmp as icmp
import pox.lib.packet.ipv4 as ip
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr


log = core.getLogger()

table={}

rules=[
# => you need now to add other rules to satisfy the assignment requirements. Notice that we will make decisions based on Ethernet address rather than IP address. Rate limiting is implemented by sending the pacet to the correct port and queue (the queues that you have specified in the topology file).
    {'EthSrc': '00:00:00:00:00:01', 'EthDst': '00:00:00:00:00:03', 'TCPPort': 40, 'queue': 0, 'drop': False},  # h1 to h3
    {'EthSrc': '00:00:00:00:00:01', 'EthDst': '00:00:00:00:00:02', 'TCPPort': 60, 'queue': 1, 'drop': False},  # h1 to h2
    {'EthSrc': '00:00:00:00:00:02', 'EthDst': '00:00:00:00:00:04', 'queue': 0, 'drop': False},  # h2 to h4
    {'EthSrc': '00:00:00:00:00:01', 'EthDst': '00:00:00:00:00:04', 'drop': False},  # h1 to h4
    {'EthSrc': '00:00:00:00:00:04', 'EthDst': '00:00:00:00:00:02', 'drop': False},  # h4 to h2
    {'EthSrc': '00:00:00:00:00:02', 'EthDst': '00:00:00:00:00:03', 'drop': False},  # h2 to h3
    {'EthSrc': '00:00:00:00:00:03', 'EthDst': '00:00:00:00:00:02', 'drop': False},  # h3 to h2
    {'EthSrc': '00:00:00:00:00:02', 'EthDst': '00:00:00:00:00:01', 'drop': False},  # h2 to h1
    {'EthSrc': '00:00:00:00:00:04', 'EthDst': '00:00:00:00:00:01', 'drop': False},  # h4 to h1
    {'EthSrc': '00:00:00:00:00:03', 'EthDst': '00:00:00:00:00:01', 'drop': False},  # h3 to h1

    {'EthSrc': '00:00:00:00:00:03', 'EthDst': '00:00:00:00:00:04', 'drop': True},  # h3 to h4 blocked
    {'EthSrc': '00:00:00:00:00:04', 'EthDst': '00:00:00:00:00:03', 'drop': True},  # h4 to h3 blocked
]

    	# => the first two example of rules have been added for you, you need now to add other rules to satisfy the assignment requirements. Notice that we will make decisions based on Ethernet address rather than IP address. Rate limiting is implemented by sending the pacet to the correct port and queue (the queues that you have specified in the topology file).

def launch ():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn",  _handle_PacketIn)
    log.info("Switch running.")

def _handle_ConnectionUp ( event):
    log.info("Starting Switch %s", dpidToStr(event.dpid))
    msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
    event.connection.send(msg)


def _handle_PacketIn ( event): # Ths is the main class where your code goes, it will be called every time a packet is sent from the switch to the controller

    dpid = event.connection.dpid
    sw=dpidToStr(dpid)
    inport = event.port     # this records the port from which the packet entered the switch
    eth_packet = event.parsed # this parses  the incoming message as an Ethernet packet
    log.debug("Event: switch %s port %s packet %s" % (sw, inport, eth_packet)) # this is the way you can add debugging information to your text

    ######################################################################################
    ############ CODE SHOULD ONLY BE ADDED BELOW  #################################

    # ==> write code here that associates the given port with the sending node using the source address of the incoming packet
    # ==> if available in the table this line determines the destination port of the incoming packet
    table[(dpid, eth_packet.src)] = inport
    dst_port = table.get((dpid, eth_packet.dst))


    # this part is now separate from next part and deals with ARP messages

    if dst_port is None and eth_packet.type == eth.ARP_TYPE and eth_packet.dst == EthAddr(b"\xff\xff\xff\xff\xff\xff"):
        # => in this case you want to create a packet so that you can send the message as a broadcast
        # ARP broadcast
        msg = of.ofp_packet_out(data=event.ofp)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
        event.connection.send(msg)
        
    for rule in rules: #now you are adding rules to the flow tables like before. First you check whether there is a rule match based on Eth source and destination
        if eth_packet.dst == EthAddr(rule['EthDst']) and eth_packet.src == EthAddr(rule['EthSrc']):# => now you are adding rules to the flow tables like before. First you check whether there is a rule match based on Eth source and destination as in assignment 1, but you need to adapt this for the case of more than 1 switch
            # => start creating a new flow rule for mathcing the ethernet source and destination'
            msg = of.ofp_flow_mod()
            msg.priority = 500
            msg.match.dl_src = eth_packet.src 
            msg.match.dl_dst = eth_packet.dst 
            msg.hard_timeout = 40

            
            # => now check if the rule contains also TCP port info. If not install the flow without any port restriction
            if 'TCPPort' in rule and eth_packet.find('tcp'):
                tcp_packet = eth_packet.find('tcp')
                if tcp_packet.dstport == rule['TCPPort']:
                    msg.match.nw_proto = 6
                    msg.match.tp_dst = rule['TCPPort']
                    break
            
            # => also remember to check if this is a drop rule. The drop function can be added by not sending any action to the flow rule
            if rule.get('drop'):
                msg.priority = 4000
                event.connection.send(msg)
                return
                
            # => also remember that if there is a QoS requirement, then you need to use the of.ofp_action_enqueue() function, instead of the of.ofp_action_output
            if 'queue' in rule:
                msg.actions.append(of.ofp_action_enqueue(port = (dst_port), queue_id = rule['queue']))

            else:
            # => and remember that in addition to creating a fow rule, you should also send out the message that came from the Switch 
                msg.actions.append(of.ofp_action_output(port=dst_port))


            # => at the end remember to send out both flow rule and packet
            event.connection.send(msg)

        # => otherwise:
        # => if the packet is an IP packet, its protocol is TCP, and the TCP port of the packet matches the TCP rule above
            # => add additioinal matching fileds to the flow rule you are creating: IP-protocol type, TCP_protocol_type, destination TCP port.
            # => like above if it requires QoS then use the of.ofp_action_enqueue() function
            # => also remember to check if this is a drop rule.
            # => at the end remember to send out both flow rule and packet
        
        if not rule.get('drop'):
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=dst_port))
            event.connection.send(msg)
          
