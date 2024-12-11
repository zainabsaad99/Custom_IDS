"""Zainab Saad
   ID:202472448"""
from scapy.all import sniff, IP, TCP
from collections import defaultdict, deque
import time
from main_config_file import get_variable,read_file,log_to_file, check_rule_match

# load rule files from a json 
rules = read_file("rules.json")

# how many packet to check in each timestamp
thresold_variable, seconds_variable = get_variable(rules, "tcp", "flood")

# This is the memory that store source of the packet where a threshold is considered
# maxlen indicate the threshold of a unique source ip to store timestamp for the most recent threshold number
store_syn_flood_source = defaultdict(lambda: deque())
store_syn_flood_destination = defaultdict(lambda: deque())


def detect_syn_flood(packet):
    """
    This function checks the syn flood attack if it is occurs 
    It first check if the source, destination Ip and source, destination  port  if matches a rule
    then check is the SYN packets from a unique Ip are sent within a time 
    """
    global store_syn_flood_source
    global store_syn_flood_destination
    # get source, destination IP, and source, destination port
    source_ip = packet[IP].src  
    destination_ip = packet[IP].dst 
    source_port = packet[TCP].sport 
    destination_port = packet[TCP].dport 
    # check for rule that matches protocl , attack types and for source/destination ip, and port 
    rule = check_rule_match(source_ip, destination_ip, source_port, destination_port, rules, "tcp", "flood"  )
    # Current timestamp
    current_time = time.time()  
    # if rule matches 
    if rule:
        
        # this to detect based on a sourcee to a specific destination
        interaction_name = source_ip +", " +destination_ip
        # Update memory for this source IP
        store_syn_flood_source[interaction_name].append(current_time)
        # if different ip is sent attack this will detect that it exceed the threshold on a destination
        store_syn_flood_destination[destination_ip].append(current_time)

        while store_syn_flood_source[interaction_name] and store_syn_flood_source[interaction_name][0] < current_time - seconds_variable:
            store_syn_flood_source[interaction_name].popleft()
            

        while store_syn_flood_destination[destination_ip] and store_syn_flood_destination[destination_ip][0] < current_time - seconds_variable:
            store_syn_flood_destination[destination_ip].popleft()
        
       
        if len(store_syn_flood_source[interaction_name]) >= thresold_variable:
            
     
                # alert attack message provided in the rule 
            message = f"{rule['message']}: {source_ip}.{source_port} --> {destination_ip}.{destination_port}"
           
                # output message in the log file
            log_to_file(message) 
        elif len(store_syn_flood_destination[destination_ip]) >= thresold_variable:
         

                    # alert attack message provided in the rule 
            message = f"{rule['message']}: {source_ip}.{source_port} --> {destination_ip}.{destination_port}"
           
                    # output message in the log file
            log_to_file(message) 


def synflood_processor(packet):
    """
    This is the main function for SYN_Flood attacks
    That will check the sniff packet if it has a TCP, IP
    
    """
    if packet.haslayer(TCP) and packet.haslayer(IP):
        # then get the TCP layer
        tcp_layer = packet[TCP]
        # check if it is a flags = s (open connection)
        if tcp_layer.flags == "S":
            # match that then check if it exceed the threshold within a time for a unique IP
            detect_syn_flood(packet)

