import scapy.all as scapy
from scapy.layers.http import HTTPResponse
import sys

def packet_filter(pcap_file, filter):
    packet_filtering = scapy.sniff(offline=pcap_file, filter= filter)
    res = b''
    ip_dest=''
    ip_source=''
    for p in packet_filtering:
        if HTTPResponse in p and not ip_source:
            body = p[HTTPResponse]
            ip_source = p[scapy.IP].src
            ip_dest = p[scapy.IP].dst
            res = bytes(p[HTTPResponse].payload)
            continue
        if ip_source == p[scapy.IP].src:
            res+= bytes(p[scapy.TCP].payload)

    open('data.raw','wb').write(res)

pcap_file = sys.argv[1]
filter = sys.argv[2]

packet_filter(pcap_file, filter)