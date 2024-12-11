"""zainab saad
    202472448"""
from main_config import validate_ip, validate_ports
from scapy.all import TCP, send, IP

# to run in ubuntu
# sudo python3 path_to_file/port_scanning.py

# ask user to enter ip of the target machine
target_ip = validate_ip("Enter target IP: ")
# ask user to enter start port, and end port
start_port, end_port = validate_ports()




def port_scanning_attack(target_ip, start_port, end_port):
    packets = []
    # loop through port from the start to the end
    for port in range(start_port, end_port+1):
        # create ip layer that contain detination ip for target machine 
        ip_layer = IP(dst=target_ip)

        # create full packet by combining the ip and tcp layer
        # set TCP flag to s to make an intial handshake   
        packet = ip_layer / TCP(dport=port, flags="S")

        # append all packet that want to sned 
        packets.append(packet)
    send(packets, verbose=False)


port_scanning_attack(target_ip, start_port, end_port)
