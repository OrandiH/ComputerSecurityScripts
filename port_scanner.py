# !/usr/bin/python
# Author:Orandi Harris

import socket
import sys
import datetime
import time
import argparse
import os
import nmap

check = 0
os.system('clear')
line = "-" * 80
desc = line +'''\nA Simple port scanner in python\n''' + line + "\n"

parser = argparse.ArgumentParser(description = desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('host', metavar='H', help='Host name you want to scan')
parser.add_argument('startport', metavar='P1', nargs='?', help='Start scanning from this port')
parser.add_argument('endport', metavar='P2', nargs='?', help='Scan until this port')
args = parser.parse_args()
nm = nmap.PortScanner()
host = args.host
ip = socket.gethostbyname(host)

if(args.startport) and args.endport:
    startport = int(args.startport)
    endport = int(args.endport)
else:
    check = 1

openPorts = []
common_ports = {
    '21': 'FTP',
    '22': 'SSH',
    '23': 'TELNET',
    '25': 'SMTP',
    '53': 'DNS',
    '69': 'TFTP',
    '80': 'HTTP',
    '109': 'POP2',
    '110': 'POP3',
    '123': 'NTP',
    '137': 'NETBIOS-NS',
    '138': 'NETBIOS-DGM',
    '139': 'NETBIOS-SSN',
    '143': 'IMAP',
    '156': 'SQL-SERVER',
    '389': 'LDAP',
    '443': 'HTTPS',
    '546': 'DHCP-CLIENT',
    '547': 'DHCP-SERVER',
    '995': 'POP3-SSL',
    '993': 'IMAP-SSL',
    '2086': 'WHM/CPANEL',
    '2087': 'WHM/CPANEL',
    '2082': 'CPANEL',
    '2083': 'CPANEL',
    '3306': 'MYSQL',
    '8443': 'PLESK',
    '10000': 'VIRTUALMIN/WEBMIN'
}

start_Time = time.time()
print "+" * 40
print "\tSimple Port Scanner!"
print "+" * 40

if(check):
    print "Scanning for most common ports"
else:
    print "Scanning %s from port %s - %s: " % (host, startport, endport)
print "Scanning started at %s" % (time.strftime("%I:%M:%S %p"))

def check_port(host, port, result = 1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        r = sock.connect_ex((host, port))
        if r == 0:
            result = r
        sock.close()
    except Exception, e:
        pass
    return result


def get_service(port):
    port = str(port)
    if port in common_ports:
        return common_ports[port]
    else:
        return 0

try:
    print "Scan in progres..."
    print "Connecting to port: ",

    if check:
        for Port in sorted(common_ports):
            sys.stdout.flush()
            Port = int(Port)
            print Port,
            response = check_port(host, Port)
            if response == 0:
                openPorts.append(Port)
                sys.stdout.write('\b' * len(str(Port)))
    else:
        for Port in range(startport, endport + 1):
            sys.stdout.flush()
            print Port,
            response = check_port(host, Port)
            if response == 0:
                openPorts.append(Port)
            if not Port == endport:
                sys.stdout.write('\b' * len(str(Port)))
    print "\nScanning completed at %s" % (time.strftime("%I:%M:%S %p"))
    nm.scan(host, arguments='-O')
    end_Time = time.time()
    total_time = end_Time - start_Time
    print "=" * 40
    print "\tScan Report: %s" % (host)
    print "=" * 40
    if total_time <= 60:
        total_time = str(round(total_time, 2))
        print "Scan Took %s seconds" % (total_time)
    else:
        total_time = total_time / 60
        print "Scan Took %s Minutes" % (total_time)

    if openPorts:
        print "Open Ports: "
        print "\tPort Service Status"
        for i in sorted(openPorts):
            service = get_service(i)
            if not service:
                service = "Unknown service"
            print "\t%s %s: Open" % (i, service)
    else:
        print "Sorry, No open ports found!"
    print "Possible OS Version of host %s" % (host)
    for osmatch in nm[host]['osmatch']:
        print('Os name : {0}'.format(osmatch['name']))
        print('')
except KeyboardInterrupt:
    print "You pressed Ctrl + C. Exiting"
    sys.exit(1)






