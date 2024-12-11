"""Zainab Saad
   ID:202472448"""
from scapy.all import sniff, UDP, DNS, IP
import time
from collections import defaultdict, deque
from main_config_file import get_variable,read_file,log_to_file, check_rule_match

# load rule files from a json 
rules = read_file("rules.json")

# how many packet to check in each timestamp
thresold_variable, seconds_variable = get_variable(rules, "udp", "dns_amp")

# This is the memory that store source of the packet where a threshold is considered
# maxlen indicate the threshold of a unique source ip to store timestamp for the most recent threshold number
store_dns_amp_source= defaultdict(lambda: deque())
store_dns_amp_destination= defaultdict(lambda: deque())

# Thresholds for detection length of DNS packets
DNS_REPLY_BYTE_THRESHOLD = 500



# DNS amplification detection based on threshold within a time
def detect_dns_amplification(packet):
  
    # get source, destination IP, and source, destination port
    source_ip = packet[IP].src  
    destination_ip = packet[IP].dst 
    source_port = packet[UDP].sport 
    destination_port = packet[UDP].dport 
 
    # check for rule that matches protocl , attack types and for source/destination ip, and port 
    rule = check_rule_match(source_ip, destination_ip, source_port, destination_port, rules, "udp", "dns_amp" )
 
    # if rule matches 
    if rule:
        # Current timestamp
        current_time = time.time()  
        interaction_name = source_ip +", " +destination_ip
        # Update memory for this source IP
        store_dns_amp_source[interaction_name].append(current_time)
        # if different ip is sent attack this will detect that it exceed the threshold on a destination
        store_dns_amp_destination[destination_ip].append(current_time)

        while store_dns_amp_source[interaction_name] and store_dns_amp_source[interaction_name][0] < current_time - seconds_variable:
            store_dns_amp_source[interaction_name].popleft()

        while store_dns_amp_destination[destination_ip] and store_dns_amp_destination[destination_ip][0] < current_time - seconds_variable:
            store_dns_amp_destination[destination_ip].popleft()

        if len(store_dns_amp_source[interaction_name]) >= thresold_variable:
         
     
            # alert attack message provided in the rule 
            message = f"{rule['message']}: {source_ip}.{source_port} --> {destination_ip}.{destination_port}"
            # output message in the log file
            log_to_file(message) 
        elif  len(store_dns_amp_destination[destination_ip]) >= thresold_variable:
          
          
            # alert attack message provided in the rule 
            message = f"{rule['message']}: {source_ip}.{source_port} --> {destination_ip}.{destination_port}"
           
            # output message in the log file
            log_to_file(message) 
        

def dns_amp_processor(packet):
      # check for message if it has IP, UDP, DNS layer
      if packet.haslayer(UDP) and packet.haslayer(IP) and packet.haslayer(DNS):
        dns_layer = packet.getlayer(DNS)
        # check that this is a DNS responce 
        if dns_layer.qr == 1:  
            # this udp from port 53 and the length of this amplification is above the threshold or equals
            if packet[UDP].sport == 53 and len(packet) >= DNS_REPLY_BYTE_THRESHOLD:
                detect_dns_amplification(packet)
       
               
