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

rules=[{'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:03', 'TCPPort':40, 'queue':0, 'drop':False},
       {'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:02', 'TCPPort':60, 'queue':1, 'drop':False}
    	# => the first two example of rules have been added for you, you need now to add other rules to satisfy the assignment requirements. Notice that we will make decisions based on Ethernet address rather than IP address. Rate limiting is implemented by sending the pacet to the correct port and queue (the queues that you have specified in the topology file).
       {'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:04', 'TCPPort': None, 'queue': 0, 'drop': False},  # h1 to h4 uncapped
       {'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:04', 'TCPPort': None, 'queue': 1, 'drop': False},  # 200Mb/s cap for h2 to h4 
       {'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:04', 'TCPPort': None, 'queue': None, 'drop': True},  #block h3 to H4 
       {'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:02', 'TCPPort': None, 'queue': 0, 'drop': False},  # no cap on h4 to H2 
       {'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:03', 'TCPPort': None, 'queue': None, 'drop': True},  #block h4 to h3 
        ]

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

    table[(dpid,eth_packet.src)] = event.port   # this associates the given port with the sending node using the source address of the incoming packet
    dst_port = table.get((dpid,eth_packet.dst)) # if available in the table this line determines the destination port of the incoming packet

# this part is now separate from next part and deals with ARP messages

    ######################################################################################
    ############ CODE SHOULD ONLY BE ADDED BELOW  #################################

    if dst_port is None and eth_packet.type == eth.ARP_TYPE and eth_packet.dst == EthAddr(b"\xff\xff\xff\xff\xff\xff"): # this identifies that the packet is an ARP broadcast
        # => in this case you want to create a packet so that you can send the message as a broadcast
        #   If ARP, extract the request
        request = eth_packet.payload

        # ARP reply
        arp_reply = pkt.arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = eth_packet.dst  #  MAC for the switch
        arp_reply.hwdst = request.hwsrc
        arp_reply.protosrc = request.protodst
        arp_reply.protodst = request.protosrc

        # Ethernet frame
        eth_reply = pkt.ethernet()
        eth_reply.type = eth.ARP_TYPE
        eth_reply.src = arp_reply.hwsrc
        eth_reply.dst = eth_packet.src  # Send directly to the requester
        eth_reply.payload = arp_reply

        # Send the ARP reply to the host
        msg = of.ofp_packet_out()
        msg.data = eth_reply.pack()
        msg.actions.append(of.ofp_action_output(port=inport))  # Send directly to the source port
        event.connection.send(msg)
        return


    for rule in rules: #now you are adding rules to the flow tables like before. First you check whether there is a rule match based on Eth source and destination
        if (eth_packet.dst==EthAddr(rule['EthDst']) and eth_packet.src==EthAddr(rule['EthSrc'])):
            log.debug("Event: found rule from source %s to dest  %s" % (eth_packet.src, eth_packet.dst))
            # => start creating a new flow rule for mathcing the ethernet source and destination
            if rule['TCPPort'] == 0:
                flow_mod = of.ofp_flow_mod()
                flow_mod.match = of.ofp_match(dl_src=eth_packet.src, dl_dst=eth_packet.dst)
                if rule['drop']:
                    flow_mod.command = of.OFPFC_DELETE
                else:
                    flow_mod.actions.append(of.ofp_action_output(port=dst_port))
                event.connection.send(flow_mod)

        else:
            if eth_packet.type == eth.IP_TYPE and isinstance(eth_packet.payload, ip.ipv4):
                ip_packet = eth_packet.payload
                if ip_packet.protocol == ip.ip_inip.TCP_PROTOCOL:
                    tcp_packet = ip_packet.payload
                    if tcp_packet.dstport == rule['TCPPort']:
                        flow_mod = of.ofp_flow_mod()
                        flow_mod.match = of.ofp_match(dl_src=eth_packet.src, dl_dst=eth_packet.dst, nw_proto=ip.ip_inip.TCP_PROTOCOL, tp_dst=tcp_packet.dstport)
                        if rule['drop']:
                            flow_mod.command = of.OFPFC_DELETE
                        else:
                            flow_mod.actions.append(of.ofp_action_enqueue(queue_id=rule['queue'], port=dst_port))
                        event.connection.send(flow_mod)

        #output results
        msg = of.ofp_packet_out(action=[of.ofp_action_output(port=event.port)], data=event.data)
        event.connection.send(msg)
        break
            #if ...
            # => now check if the rule contains also TCP port info. If not install the flow without any port restriction
                # => also remember to check if this is a drop rule. The drop function can be added by not sending any action to the flow rule
                # => also remember that if there is a QoS requirement, then you need to use the of.ofp_action_enqueue() function, instead of the of.ofp_action_output
                # => and remember that in addition to creating a fow rule, you should also send out the message that came from the Switch
                # => at the end remember to send out both flow rule and packet

            #else ...
            # => otherwise:
            # => if the packet is an IP packet, its protocol is TCP, and the TCP port of the packet matches the TCP rule above
                # => add additioinal matching fileds to the flow rule you are creating: IP-protocol type, TCP_protocol_type, destination TCP port.
                # => like above if it requires QoS then use the of.ofp_action_enqueue() function
                # => also remember to check if this is a drop rule.
                # => at the end remember to send out both flow rule and packet


    ########### THIS IS THE END OF THE AREA WHERE YOU NEED TO ADD CODE ##################################
    #####################################################################################################
            
