#$ git clone https://github.com/savon-noir/python-libnmap.git
#$ cd python-libnmap
#$ python setup.py install

import optparse
import socket
from socket import *
from libnmap.parser import NmapParser


def connScanTCP(tgtHost, tgtPort, tgtService):
    try:
        client = socket(AF_INET, SOCK_STREAM)
        client.connect((tgtHost, int(tgtPort)))
        if ("http" in str(tgtService) or "https" in str(tgtService)):
            client.send('HEAD / HTTP/1.1\r\nHost: google.com\r\n\r\n')
        else:
            client.send('Woot Woot ... Root\r\n')
        results = client.recv(4096)
        print '[+]%d/tcp open'% tgtPort
        print '[+] ' + str(results)
        client.close()
    except Exception, e:
        print '[-]%d/tcp closed'% tgtPort
        print '[-] Error: ' + str(e)
        setdefaulttimeout(1)
        
def connScanUDP(tgtHost, tgtPort):
    try:
        client = socket(AF_INET, SOCK_DGRAM)
        client.sendto("wootwootroot",(target_host,int(target_port)))
        data, addr = client.recvfrom(4096)
        print '[+]%d/udp open'% tgtPort
        print '[+] ' + str(results)
        
    except Exception, e:
        print '[-]%d/udp closed'% tgtPort
        print '[-] Error: ' + str(e)
        setdefaulttimeout(1)

def nmapXml(tgtFile):
    try:
        nmap_report = NmapParser.parse_fromfile(tgtFile)
        for host in nmap_report.hosts:
            for (port,proto) in host.get_ports():
                print '[+] Scanning port ' + str(port) + ' on ' + host.address
                if (proto=="tcp"):
                    connScanTCP(host.address, port,host.get_service(int(port),proto))
                else :
                    connScanUDP(host.address, port)
                
            
    except Exception, e:
        print '\n[-] Error in parsing XMl file: ' + tgtFile
        print '[-] Error: ' + str(e)
        setdefaulttimeout(1)
    
    

def main():
    parser = optparse.OptionParser("usage%prog "+"-F <XML File name> ")
    parser.add_option('-F', dest='tgtFile', type='string',help='specify target nmap file')
    (options, args) = parser.parse_args()
    tgtFile = options.tgtFile
    #print tgtFile
    if (tgtFile == None) :
        print '[-] You must specify a Xml File.'
        parser.print_help()
        exit(0)
    else:
        nmapXml(tgtFile)


if __name__ == '__main__':
    main()



    