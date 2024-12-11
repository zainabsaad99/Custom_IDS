"""Zainab Saad
   ID:202472448"""
from scapy.all import sniff, IP, UDP
from collections import defaultdict, deque
import time
import json
from main_config_file import get_variable,read_file,log_to_file, check_rule_match

# load rule files from a json 
rules = read_file("rules.json")

# how many packet to check in each timestamp
thresold_variable, seconds_variable = get_variable(rules, "udp", "flood")

# To store interaction name between source and destination within time (second_variable)
store_udp_flood_source = defaultdict(lambda: deque())
# # To store interaction name between destination within time (second_variable)
store_udp_flood_destination = defaultdict(lambda: deque())

def udpflood_processor(packet):
    """
    Process packets to detect UDP flood attacks.
    Check if it is a UDP before check
    """
    if packet.haslayer(UDP) and packet.haslayer(IP):
        check_udp_flood(packet)



def check_udp_flood(packet):
    """
    Checks for UDP flood attacks and generates alerts.
    """
    
    # get source, destination IP, and source, destination port
    source_ip = packet[IP].src  
    destination_ip = packet[IP].dst 
    source_port = packet[UDP].sport 
    destination_port = packet[UDP].dport 
 
    # check for rule that matches protocl , attack types and for source/destination ip, and port 
    rule = check_rule_match(source_ip, destination_ip, source_port, destination_port, rules, "udp", "flood"  )
    # Current timestamp
    current_time = time.time() 
    # if rule matches 
    if rule:
         
        # this to detect based on a sourcee to a specific destination
        interaction_name = source_ip +", " +destination_ip
        # Update memory for this source IP
        store_udp_flood_source[interaction_name].append(current_time)
        # if different ip is sent attack this will detect that it exceed the threshold on a destination
        store_udp_flood_destination[destination_ip].append(current_time)

        # to remove packets that is not within the second_variable for interaction name
        while store_udp_flood_source[interaction_name] and store_udp_flood_source[interaction_name][0] < current_time - seconds_variable:
            store_udp_flood_source[interaction_name].popleft()

        # to remove packets that is not within the second_variable for destination name
        while store_udp_flood_destination[destination_ip] and store_udp_flood_destination[destination_ip][0] < current_time - seconds_variable:
            store_udp_flood_destination[destination_ip].popleft()

        # if the number of packets for interaction_name above threshold
        if len(store_udp_flood_source[interaction_name]) >= thresold_variable:
            # alert attack message provided in the rule 
            message = f"{rule['message']}: {source_ip}.{source_port} --> {destination_ip}.{destination_port}"   
            # output message in the log file
            log_to_file(message) 
        # IF interaction name is not above the threshold then this condition will test
        # this is important if attack comes from different IP 
        # check if destination above threshold
        elif  len(store_udp_flood_destination[destination_ip]) >= thresold_variable:
         
          
            # else output message 
            # alert attack message provided in the rule 
            message = f"{rule['message']}: {source_ip}.{source_port} --> {destination_ip}.{destination_port}"
            # output message in the log file
            log_to_file(message) 
