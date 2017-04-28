# Packet sniffer
import socket
import sys
from struct import *

# creating ethernet header
def eth_address(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b

# Creating a socket
try:  
    sock = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error ,msg:
    print 'Socket could not be created. Error code: ' + str(msg[0]) + 'Message' + msg[1]
    sys.exit()


# Receiving a packet
try:

    while True:
        packet = sock.recvfrom(65565)
        # get packet data and place in tuple
        packet = packet[0]

        # parse ethernet header
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_proto = socket.ntohs(eth[2])
        print 'Destination MAC : ' + eth_address(packet[0:6]) + '\n'
        print 'Source MAC : ' + eth_address(packet[6:12]) + '\n'
        print 'Protocol :  ' + str(eth_proto) + '\n'

        # Parse IP packets, IP protocol number = 8
        if eth_proto == 8:
            # place first 20 characters into tuple,this is ip header
            ip_header = packet[eth_length:20 + eth_length]
            # unpack IP header
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4
            # Time to live
            ttl = iph[5]
            protocol = iph[6]
            source_addr = socket.inet_ntoa(iph[8])
            desti_addr = socket.inet_ntoa(iph[9])

            print 'Version : ' + str(version) + '\n'
            print 'IP Header length : ' + str(ihl) + '\n'
            print 'TTL : ' + str(ttl) + '\n'
            print 'Protocol : ' + str(protocol) + '\n'
            print 'Source Address : ' + str(source_addr) + '\n'
            print 'Destination Address :' + str(desti_addr) + '\n'

            # TCP protocol
            if protocol == 6:
                tcp = iph_length + eth_length
                # Set TCP Header variable
                tcp_header = packet[tcp:tcp + 20]

                # Unpack TCP header
                tcph = unpack('!HHLLBBHHH', tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                print 'Source Port : ' + str(source_port) + '\n'
                print 'Destination Port : ' + str(dest_port) + '\n'
                print 'Sequence Number : ' + str(sequence) + '\n'
                print 'Acknowledgement : ' + str(acknowledgement) + '\n'
                print 'TCP header length: ' + str(tcph_length) + '\n'

                h_size = iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                # extract data from packet

                data = packet[h_size:]
                
                Encoded_data = data.decode('utf-8','replace')
                Encoded_data.replace(u"\uFFFD", "/")
                Decoded_data = Encoded_data.encode("ascii",errors='xmlcharrefreplace')
                print 'Data: ' + Decoded_data
                print '\n'
                # ICMP packets
            elif protocol == 1:
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u + 4]
                # Now unpack
                icmph = unpack('!BBH', icmp_header)
                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]

                print 'Type : ' + str(icmp_type) + '\n'
                print 'Code : ' + str(code) + '\n'
                print 'Checksum : ' + str(checksum)

                h_size = eth_length + icmph_length
                data_size = len(packet) - h_size

                # Get data from packet
                data = packet[h_size:]
                # Processing data packet
                Encoded_data = data.decode('utf-8', 'replace')
                Encoded_data.replace(u"\uFFFD", "/")
                Decoded_data = Encoded_data.encode("ascii", errors='xmlcharrefreplace')
                print 'Data: ' + Decoded_data
                print '\n'
                # UDP packets
            elif protocol == 17:
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u + 8]

                # Unpack
                udph = unpack('!HHHH', udp_header)
                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                print 'Source Port : ' + str(source_port) + '\n'
                print 'Destination: ' + str(dest_port) + '\n'
                print 'Length: ' + str(length) + '\n'
                print 'Checksum: ' + str(checksum) + '\n'

                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size
                # Get data from packet
                data = packet[h_size:]
                # Processing data packet
                Encoded_data = data.decode('utf-8', 'replace')
                Encoded_data.replace(u"\uFFFD", "/")
                Decoded_data = Encoded_data.encode("ascii", errors='xmlcharrefreplace')
                print 'Data: ' + Decoded_data
                print '\n'
            else:
                print 'Protocol other than TCP/UDP/ICMP'
except KeyboardInterrupt:
    print "You pressed Ctrl + c, Exiting.."
    sys.exit(1)














    

    
