from scapy.all import sniff, IP, TCP
from scapy.layers.tls.handshake import TLSClientHello

def capture(packet):#Packet capture function
    print("Packet Captured\n")
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return None
    return packet
sniff(iface="any", filter ="tcp port 443 or tcp port 80", prn=capture, store=0)
# Sniff is an inbuilt function that works with NIC to capture packets, 
# iface the interface we are using
# filter is we are capturing trffic on tcp port 443 and 80 only i.e HTTP & HTTPS No UDP 
# prn is an inbuilt module that repeatedly calls our function that is capture
# store is a function if we want to store the captured packets in a file 0 means FALSE


    