import scapy.all as scapy


i = scapy.IP(dst="185.235.207.35")
t = scapy.TCP(dport=22, seq=1000, flags="S")
sa = scapy.sr1(i/t)
a = t
a.seq=sa.ack;a.flags="A";a.ack=sa.seq+1
b = scapy.sr1(i/a)

#ap = a
#ap.seq=a.seq+1;ap.flags="AP"
#b = scapy.sr1(i/ap)

print(b.show())
a2=a
a2.seq = b.ack;a2.ack=b.seq+len(b[scapy.TCP].payload)
scapy.send(i/a2)
f = a2
f.flags = "FA";f.seq = b.ack; f.ack = b.seq + len(b[scapy.TCP].payload)
fa = scapy.sr1(i/f)
l=f
l.seq = fa.ack; l.ack = fa.seq+1; l.flags = "A"
scapy.send(i/l)
