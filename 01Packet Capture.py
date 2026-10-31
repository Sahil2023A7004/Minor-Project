from scapy.all import sniff, IP, TCP
from scapy.layers.tls.handshake import TLSClientHello

def capture(packet):#Packet capture function
    print("Packet Captured\n")
    if packet.haslayer(TLSClientHello):#Check if packet has TLS Hello
        print("TLS Detected\n")
        print(packet.show())#Printing the TLS Hello
        hello = packet[TLSClientHello]#hello Veriable saves the Captured TLS Hello
        ciphers = hello.ciphers #Ciphers stores TLS ciphers suites
        print(f"Supported ciphers: {ciphers}")
        version = hello.version #TLS verion
        print(f"Supported TLS version: {version}")
        src_ip = packet[IP].src #Source IP
        dst_ip = packet[IP].dst #Destination Ip
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}") #Source and Destination Port
sniff(iface="any", filter ="tcp port 443 or tcp port 80", prn=capture, store=0)
# Sniff is an inbuilt function that works with NIC to capture packets, 
# iface the interface we are using
# filter is we are capturing trffic on tcp port 443 and 80 only i.e HTTP & HTTPS No UDP 
# prn is an inbuilt module that repeatedly calls our function that is capture
# store is a function if we want to store the captured packets in a file 0 means FALSE


    