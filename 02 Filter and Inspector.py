from scapy.all import sniff, IP, TCP
from scapy.layers.tls.handshake import TLSClientHello

def metadata(packet):
        source_ip = packet["IP"].src
        destination_ip = packet["IP"].dst
        time_to_live = packet["IP"].ttl
        source_port = packet["TCP"].sport
        destination_port = packet["TCP"].dport
        flags = str(packet["TCP"].flags)
        packet_size = len(packet)
        master_directory = {
                "source_type": "network",
                "protocol": "tcp",
                "source_ip": source_ip,
                "dest_ip": destination_ip,
                "source_port": source_port,
                "dest_port": destination_port,
                "tcp_flags": flags,
                "packet_size": packet_size,
                "ja4": None,
                "event_type": "TCP",
                "metadata":{
                "time_to_live": time_to_live,
                "sni": None
                }
                }
        return master_directory
def ja4(packet):
        GREASE_TABLE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 
    0xcaca, 0xdada, 0xeaea, 0xfafa
}
        if not packet.haslayer(TLSClientHello):
                return None
        else:
         hello = packet[TLSClientHello]
         ciphers = hello.ciphers
         clean_ciphers = []
         for c in ciphers:
               if c not in GREASE_TABLE:
                     clean_ciphers.append(c)
               else:
                continue  
         clean_extensions = []
        extentions = hello.ext
        for e in extentions:
         if e.type not in GREASE_TABLE:
          clean_extensions.append(e.type)
        c_count = f"{min(len(clean_ciphers), 99):02d}"
        e_count = f"{min(len(clean_extensions), 99):02d}"
        
          



