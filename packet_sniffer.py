
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import scapy.layers.inet
import scapy.packet
import scapy.utils

def packet_sniffer(packet):
    
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"[IP] {ip_layer.src}->{ip_layer.dst}")
    elif packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        print(f"[TCP] {tcp_layer.src} -> {tcp_layer.dst}")
    elif packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        print(f"[UDP] {udp_layer.src} -> {udp_layer.dst}")
    elif packet.haslayer(ICMP):
        icmp_layer = packet.getlayer(ICMP)
        print(f"[ICMP] {icmp_layer.src} -> {icmp_layer.dst}")
print("\n")


sniff(packet_sniffer, store=0)

    