"""Zainab Saad
   ID:202472448"""
import json
import time
import os


# This function is used to load messages from the json file
# message allow user to trak a specific id and port for target and victim
# also allow to specify protocl (tcp,arp,udp....) and type of attacks
# also it contain a message to alert, threshold, and time to check threshold in it
def read_file(filename):
    # open  file based on their name
    if not os.path.exists(filename):
        log_error(f"Error: The rule file does not exist.")
        return None
    
    if os.path.getsize(filename) == 0:
        log_error(f"Error: The rule file is empty.")
        return None
        
    with open(filename, 'r') as file:
        try:
            rules= json.load(file)
            if not rules:  # Check if the JSON object is empty
               log_error(f"Error: The rule file contains empty JSON.")
               return None
        except json.JSONDecodeError:
            log_error(f"Error: The rule file contains invalid JSON.")
            return None
    return rules

# This function 
# get variable from the rule that matches protocol and the attack type
# this is used to detect the threshold, and time specify for a rule
def get_variable(rules, protocol, attack_type):
    # loop through the rules 
    if not rules:
        log_error(f"Error: The rule file is empty.")
        return None, None
    for rule in rules:
        # when a rule matches the protocol and attack_type  
        if rule["protocol"] == protocol and rule["attack_type"] == attack_type: 
            # return the value of threshold, and time 
            return rule['threshold'], rule["seconds"]
        

# this function output message  in log file 
# all the message start with the time and then message as mention in the rule     
def log_to_file(message):
    with open("log.txt", "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def log_error(message):
    with open("log_error.txt", "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

# check if there a rule match the source/destination Ip, and port for a specific protocol/attack_type
def check_rule_match(src_ip, dst_ip, src_port, dst_port,rules ,protocol,attack_type):
    if not rules:
        log_error(f"Error: The rule file is empty.")
        return None
    
    # loop through rules to match them with the ip and port
    for rule in rules:
        # check for a specific protocol and attack types 
        if rule["protocol"] == protocol and rule["attack_type"] == attack_type: 
          
            # Check if rule matches: the packet IPs and ports
            # the packet IPs or any
            # the packets port or any
            if (rule["src_ip"] == "any" or rule["src_ip"] == str(src_ip)) and \
               (rule["dst_ip"] == "any" or rule["dst_ip"] == str(dst_ip)) and \
               (rule["src_port"] == "any" or rule["src_port"] == str(src_port)) and \
               (rule["dst_port"] == "any" or rule["dst_port"] == str(dst_port)):
                # if match return this rule
                return rule
    # else return none
    return None