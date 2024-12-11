"""Zainab Saad
   ID:202472448"""
from scapy.all import sniff, IP, ICMP
from collections import deque, defaultdict
import time
from main_config_file import get_variable,read_file,log_to_file, check_rule_match


"""rules: this variable load rules of IDS that are in json format"""
rules = read_file("rules.json")

"""This variable get from rules the threshold and time in seconds"""
thresold_variable, seconds_variable = get_variable(rules, "icmp", "flood")

"""This variable is a queue that store icmp recieved during time specify in the rules"""
store_icmp_flood_source=  defaultdict(lambda: deque())
store_icmp_flood_destination = defaultdict(lambda: deque())

def icmpflood_processor(packet):
    """
    This Function is used to process the packet that are ICMP to detect if attack
    take place by calling the check_ismp_flood function 
    """
    if packet.haslayer(ICMP) and packet.haslayer(IP):
        check_icmp_flood(packet)

def check_icmp_flood(packet):
    """
    This function checks packet during that recieved within the time variable (second_variable)
    if it reach the threshold then an attack take place, and alert message is then display to snort file
    """
    # get source, destination IP, and source, destination port
    source_ip = packet[IP].src  
    destination_ip = packet[IP].dst 

    # Current timestamp
    current_time = time.time()  

    # check for rule that matches protocl , attack types and for source/destination ip, and port 
    rule = check_rule_match(source_ip, destination_ip, "any", "any", rules, "icmp", "flood"  )
 
    # if rule matches 
    if rule:
      
        interaction_name = source_ip +", " +destination_ip
        # Update memory for this source IP
        store_icmp_flood_source[interaction_name].append(current_time)
       
        """This check is also apply since if the attack is sent by different source IP """
        store_icmp_flood_destination[destination_ip].append(current_time)

        while store_icmp_flood_source[interaction_name] and store_icmp_flood_source[interaction_name][0] < current_time - seconds_variable:
            store_icmp_flood_source[interaction_name].popleft()

        while store_icmp_flood_destination[destination_ip] and store_icmp_flood_destination[destination_ip][0] < current_time - seconds_variable:
            store_icmp_flood_destination[destination_ip].popleft()
        

        if len(store_icmp_flood_source[interaction_name]) >= thresold_variable:
          
     
                # alert attack message provided in the rule 
            message = f"{rule['message']}: {source_ip} --> {destination_ip}"
           
                # output message in the log file
            log_to_file(message) 
        elif  len(store_icmp_flood_destination[destination_ip]) >= thresold_variable:
          
         
     
                # alert attack message provided in the rule 
            message = f"{rule['message']}: {source_ip} --> {destination_ip}"
          
                # output message in the log file
            log_to_file(message) 

   