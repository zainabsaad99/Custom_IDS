"""Zainab Saad
   ID:202472448"""
from scapy.all import sniff, IP, TCP
from collections import defaultdict, deque
import time
import json
from main_config_file import get_variable,read_file,log_to_file, check_rule_match

# load rule files from a json 
rules = read_file("rules.json")

# how many packet to check in each timestamp
thresold_variable, seconds_variable = get_variable(rules, "tcp", "scan")

# This is the memory that store source of the packet where a threshold is considered
# maxlen indicate the threshold of a unique source ip to store timestamp for the most recent threshold number
store_port_scan = defaultdict(lambda: deque())



def portscan_processor(packet):
    """
    Process packets to detect port scanning attacks.
    """
    if packet.haslayer(TCP) and packet.haslayer(IP):

        if packet[TCP].flags == "S" or packet[TCP].flags == "SA": 
            check_portscan_attack(packet)


def check_portscan_attack(packet):
    """
    Checks for port scanning attacks and generates alerts.
    """
    # get source, destination IP, and source, destination port
    source_ip = packet[IP].src  
    destination_ip = packet[IP].dst 
    source_port = packet[TCP].sport 
    destination_port = packet[TCP].dport 
    port_scan_attack_state = False
    # check for rule that matches protocl , attack types and for source/destination ip, and port 
    rule = check_rule_match(source_ip, destination_ip, source_port, destination_port, rules, "tcp", "scan"  )
    
    # if rule matches 
    if rule:
        # Current timestamp
        current_time = time.time()  

        # Update memory for this source IP
        store_port_scan[source_ip].append(current_time)

        # check that the threshold for a unique ip exceed within a time 
        if len(store_port_scan[source_ip]) >= thresold_variable:
            # check that timestamp fall in the one specifiy in the rule 
            
                port_scan_attack_state = True
                # alert that an attack take place
                message = f"{rule['message']}: {source_ip}:{source_port} --> {destination_ip}:{destination_port}"
                # output message in the log file
                log_to_file(message) 
    if port_scan_attack_state:
        store_port_scan.clear()


