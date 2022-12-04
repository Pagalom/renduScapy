import scapy.all as scapy
import sys
from env import *


#Les types de requête : {A, AAAA, MX, NS, CNAME, TXT, PTR, SOA, SRV, HINFO, NAPTR, SPF, ANY}
try:
    if sys.argv[2] not in ["A","AAAA","MX","NS","CNAME","TXT","PTR","SOA","SRV","HINFO","NAPTR","SPF","ANY"]: raise ValueError("Type not processed ... yet")
except ValueError:
    print("ValueError on DNS type : ")
    raise

dns_req = scapy.IP(dst='8.8.8.8')/scapy.UDP(dport=53)/scapy.DNS(rd=1, qd=scapy.DNSQR(qname=sys.argv[1], qtype=sys.argv[2]))
answer = scapy.sr1(dns_req, verbose=0)

# affichage principal qui ne sert pas en l'occurence mais me sert de ref s'il faut modifier certains champs
""" def affichage(answer):
    qtype=answer.qd.qtype
    ancount = answer.ancount
    nscount = answer.nscount
    if qtype == A:
            for i in range(ancount):
                print(answer.an[i].rdata,"\t",str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(answer.ns[i].rdata,"\t",str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    elif qtype == NS:
            for i in range(ancount):
                print(answer.an[i].rdata,"\t",str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(answer.ns[i].rdata,"\t",str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    elif qtype == AAAA:
            for i in range(ancount):
                print(answer.an[i].rdata,"\t",str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(answer.ns[i].rdata,"\t",str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    elif qtype == MX:
            for i in range(ancount):
                print(str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    elif qtype == CNAME:
            for i in range(ancount):
                print(str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    elif qtype == TXT:
            for i in range(ancount):
                print(answer.an[i].rdata,"\t",str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(answer.ns[i].rdata,"\t",str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    elif qtype == PTR:
            for i in range(ancount):
                print(answer.an[i].rdata,"\t",str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(answer.ns[i].rdata,"\t",str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    elif qtype == SOA:
            for i in range(ancount):
                print(str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    elif qtype == SRV:
            for i in range(ancount):
                print(str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    elif qtype == HINFO:
            for i in range(ancount):
                print(str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    elif qtype == NAPTR:
            for i in range(ancount):
                print(str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    elif qtype == SPF:
            for i in range(ancount):
                print(str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])

 """
# Même version que avant mais vu qu'on a régulièrement le même retour sur
# les qtypes, on réunit ceux qui peuvent l'être

def affichage2(answer):
    qtype=answer.qd.qtype
    ancount = answer.ancount
    nscount = answer.nscount
    if qtype in [A,NS,AAAA,TXT,PTR]: # A NS AAAA TXT PTR
            for i in range(ancount):
                print(answer.an[i].rdata,"\t",str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(answer.ns[i].rdata,"\t",str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    
    elif qtype in [MX, CNAME, SOA, SRV, HINFO, NAPTR, SPF]: # MX CNAME SOA SRV HINFO NAPTR SPF
            for i in range(ancount):
                print(str(answer.an[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.an[i].type],"\t",scapy.dnsclasses[answer.an[i].rclass])
            for i in range(nscount):
                print(str(answer.ns[i].rrname, 'UTF-8'),"\t",scapy.dnstypes[answer.ns[i].type],"\t",scapy.dnsclasses[answer.ns[i].rclass])
    

affichage2(answer)