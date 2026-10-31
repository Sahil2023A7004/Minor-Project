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
                "metadata":{
                "time_to_live": time_to_live,
                "sni": None
                },
                "ja4": None,
                "event_type": "TCP"
                }
        return master_directory
