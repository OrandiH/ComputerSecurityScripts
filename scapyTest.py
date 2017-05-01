from scapy.all import *
import re
import base64

def http_header(packet):
        http_packet=str(packet)
        credentials = re.search(r"Authorization:\sBasic\s(.*)\r",http_packet)
        if credentials:
             cracked_credentials = credentials.group(1)
             print cracked_credentials.decode('base64')
        if http_packet.find('GET'):
            GET_Layer(packet)
            return GET_print(packet)

def GET_print(packet1):
    ret = "***************************************GET PACKET****************************************************\n"
    ret += "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    ret += "*****************************************************************************************************\n" 
    GET_Layer(packet1)
    return ret
def GET_Layer(packet1):
    http_packet = str(packet1)
    http_packet.find('Authorization: ')
    return http_packet


sniff(iface='lo', prn=http_header, filter="port 80")