"""Zainab Saad
   ID:202472448"""
from scapy.all import  ARP
import time 
from create_arp_table import update_arp_table_thread, def_copy_arp_table
from threading import Thread
from main_config_file import log_to_file, log_error, read_file, get_variable, check_rule_match

# strat update_arp table that create or update table 
update_arp_table_thread.start()

# save a copy of arp table 
create_global_table_for_arp = def_copy_arp_table()

#this is used to load rules
rules = read_file("rules.json")

# Threshold and time window for ARP spoofing detection
threshold_variable, seconds_variable = get_variable(rules, "arp", "spoofing")

# number of arp spoof packet to a target machine 
# also used to prevent update arp table when a spoof take place
number_arp_spoof_packet = 0

# memory to save info about packets
arp_request_memory = {}
arp_spoof_memory = {}

# use to reset memory that save data
arp_spoof_memory_resettable = True

# This function will be used in the detection of arp spoofing to check operation if it is request or reply
def get_arp_operation(packet):
    arp_op = None

    if not packet.haslayer(ARP):
        return arp_op

    try:
        # this resturn arp operation
        # 1: ARP request
        # 2: ARP reply
        arp_op = packet.getlayer(ARP).op
    except Exception as e:
         # write in caught error the error message which indicate no  operation value
        log_error("ARP packet has no operation value: " + str(e))

    return arp_op



# main function for arp spoof detection
def arp_spoof_processor(packet):
    
    # filtering to check if it is an ARP packets
    if not packet.haslayer(ARP):
        return

    # This function is defined in the Configuration part of the IDS which check the ARP operation
    # 1: ARP request
    # 2: ARP reply
    arp_op = get_arp_operation(packet)

    # op = 1 which is a request packet
    if arp_op == 1:
        # this will store for a short time the arp request info (requester ip/mac, requested ip) in 
        # args to pass packet to the function store_arp_request
        # Thread since deteling action not needed to be done directly need to check this data for detecting attack
        store_arp_request_thread = Thread(target=store_arp_request, args=(packet,))
        store_arp_request_thread.start()

    # op =2 which is a reply packet
    if arp_op == 2:

        # checks whether a reply matches any request stored in memory
        # True if a reply matches a request, False if not
        is_valid_reply = arp_reply(packet)

        # if reply is not valid which indicate a reply without matching request
        if not is_valid_reply:
            # get ip of the sourec packet which is the reply one, and its mac
            ip = packet.getlayer(ARP).psrc
            mac_address = packet.getlayer(ARP).hwsrc

            # check if there a match for it in the tabe
            not_spoof_packet = check_arp_table(ip, mac_address)

            #if invalid reply doesn't matches data in arp table so there is an arp spoof packet
            if not not_spoof_packet:
                # this function check if this attack occurs already btw source and destination
                # if not set arp_spoof_memory for this pair to zero
                # if yes increment arp_spoof_memory
                update_arp_spoof_memory(packet)

                mark_arp_spoof_thread = Thread(target=mark_arp_spoof)
                mark_arp_spoof_thread.start()


def update_arp_spoof_memory(packet):
  
    # since it is a spoof arp
    #  source IP address of the ARP packe
    attacker = packet.src
    #  destination IP address of the ARP packe
    target = packet.dst
   
    interaction_name = attacker+ ", " + target
    # check if it is already exist 
    if interaction_name not in arp_spoof_memory:
        #If the interaction doesn't exist yet set it for this interaction name to zero
        arp_spoof_memory[interaction_name] = 0
    # else if it is exist increment it
    arp_spoof_memory[interaction_name] += 1


# to prevent arp table from updating
# when there is a arp spoof 
# this to prevent local arp from being updated
def mark_arp_spoof():
    global number_arp_spoof_packet

    number_arp_spoof_packet += 1
    time.sleep(5)
    number_arp_spoof_packet -= 1

"""Function responsible to save source ip/mac, and ip which request has mac for a time in memory"""
# This function is build to store the arp request activites
# log for device that request mac address
def store_arp_request(packet):
    # Record for arp request send by a device to keep it:
    # This information is extracted from arp request packet
    # This identify which device ask for mac for which ip
    # get IP of the source how send request
    request_psrc = packet.getlayer(ARP).psrc 
    # get Mac of the source how send request
    request_hwsrc = packet.getlayer(ARP).hwsrc  
    # get Ip device that need its mac
    request_pdst = packet.getlayer(ARP).pdst  

    # if IP of request is not in the arp requesr memory 
    if request_psrc not in arp_request_memory:
        #  add an entry to this ip since is in the arp_request_memory
        arp_request_memory[request_psrc] = {"src_mac": [], "request_to": []}

    # This will relate IP of the requester to the requested ip, and ip that search for its mac to its mac
    arp_request_memory[request_psrc]["request_to"].append(request_pdst)
    arp_request_memory[request_psrc]["src_mac"].append(request_hwsrc)

    
    time.sleep(2)

    # after short time this entry of requster ip to the destination will be deleted
    #this step to make dictonary clean and prevent it from storing not clean data 
    # this help manage memory usage it is a performance step
    for i, pdst in enumerate(arp_request_memory[request_psrc]["request_to"]):
        if request_pdst == pdst:
            del arp_request_memory[request_psrc]["request_to"][i]
            del arp_request_memory[request_psrc]["src_mac"][i]
    # check if it is empty 
    if (
        len(arp_request_memory[request_psrc]["request_to"]) == 0
        and arp_request_memory[request_psrc]["src_mac"] == 0
    ):
        del arp_request_memory[request_psrc]

"""Function responsible to check validation of a reply packet"""
# This function take packet which is an arp reply packet 
#  check the info save in the memory then returns True if matching request packet
#  Which means  reply is valid
def arp_reply(packet):
    # Record for arp request send by a device to keep it:
    # get IP of the source how send request
    reply_psrc = packet.getlayer(ARP).psrc
    # get IP of reply device
    reply_pdst = packet.getlayer(ARP).pdst
    # mac of reply device
    reply_hwdst = packet.getlayer(ARP).hwdst

    # to see if this a valid repy for the request 
    # set variable first to false 
    is_valid_reply = False

    # check request packet in memory 
    for request_psrc in arp_request_memory:
        # if no match for the ip that send request continue 
        if not request_psrc == reply_pdst:
            continue
        # if there is a match
        # loop through the arp_request_memory 
        # give index, and value of destination ip which a requester has sent to it
        for i, request_pdst in enumerate(
            arp_request_memory[request_psrc]["request_to"]
        ):
            # if ip of destination is not the one how reply continue
            if not request_pdst == reply_psrc:
                continue
            # if mac of dest is not match the one rply continue
            if not arp_request_memory[request_psrc]["src_mac"][i] == reply_hwdst:
                continue
            # if ip, mac match set this to be true
            is_valid_reply = True
            # then delete them from memory 
            del arp_request_memory[request_psrc]["request_to"][i]
            del arp_request_memory[request_psrc]["src_mac"][i]
            # time to brak this loop
            break

    return is_valid_reply

"""Function check if information matches data in arp table"""
# checking whether an ip and mac address matches information inside arp table, returns False if it doesnt match
# only runs when invalid arp packets are found
def check_arp_table(ip, mac_address):
    matches_arp_table = False
    # if not matching if ip and mac this will return flase and true otherwise
   
    #number_arp_spoof_packet which is a global variable 
    global number_arp_spoof_packet
    # this is set to one to stop updating arp table 
    number_arp_spoof_packet += 1
  
    # check if ip is in the arp table 
    for arp_ip in create_global_table_for_arp:
        # checking ip by ip if no match continue 
        if not ip == arp_ip:
            continue
        # if ip match check its mac if it is match set varible to be true
        if create_global_table_for_arp[arp_ip] == mac_address:
            matches_arp_table = True
    # then return number of arp packet to zero to allow updating arp table
    number_arp_spoof_packet -= 1

    return matches_arp_table



def arp_spoof_detector():
    while True:
        # time for detection
        time.sleep(seconds_variable)
       
        global arp_spoof_memory_resettable
       
        spoof_attack_state = False
        # check the interaction name in the arp spoof memory which is save when invalid arp ip-mac is occurs
        for interaction_name in arp_spoof_memory:
            # split ip of the source and destination
            src_and_dst = interaction_name.split(", ")
            source_ip= src_and_dst[0]
            destination_ip= src_and_dst[1]
            rule = check_rule_match(source_ip,destination_ip, "any", "any", rules, "arp", "spoofing")
            
    
            if rule:
            
            # check time if it occurs an invalid packet
            # time of occurence compare to the threshold value
             if arp_spoof_memory[interaction_name] >= threshold_variable:
                # spoof attack is detected 
                spoof_attack_state = True
                # if it is equal to the threshold value or above
                # call function that alert message that attack is occured in log file
                message = f"{rule['message']}: {source_ip} --> {destination_ip}"
                log_to_file(message)

        if spoof_attack_state:
            arp_spoof_memory.clear()

arp_spoof_detector_thread = Thread(target=arp_spoof_detector)
