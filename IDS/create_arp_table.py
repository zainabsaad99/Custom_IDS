"""Zainab Saad
   ID:202472448"""
import json 
import scapy.all as scp
import time 
from threading import Thread

"""This is writen to create and update the arp table for the local network"""
# Global arp variable to save arp table in it to be used by IDS
create_global_table_for_arp = {}

# describe it when writing spoof 
number_arp_spoof_packet = 0


# location of arp table save in a json file 
Location_of_local_arp_table = "arp_table.json"

# Function that configure ARP table for Local  network 
def configure_local_arp_table():
    #create a dictionary to save arp table
    arp_table = {}
    # use try and except to check if table already exist or not
    try:
        # open the arp_table.json file for reading only. 
        with open(Location_of_local_arp_table, "r") as f:
            # to read an parse Json data 
            save_arp_table = json.load(f)
            # use copy() to create a separate copy of  dictionary 
            arp_table = save_arp_table.copy()
    # if file doesnt occures create it
    except:
        # call function that generate the arp table
        generation_of_arp_table = generate_arp_table()
        arp_table = generation_of_arp_table.copy()
    # writing arp table into local file
    write_arp_table(arp_table, Location_of_local_arp_table)
    # to use arp table in the IDS system copy table to a global
    configure_a_create_global_table_for_arp(arp_table)
    print("ARP table is configured")

# to get arp table to be used in arp spoofing detection
def def_copy_arp_table():
    #create a dictionary to save arp table
    arp_table = {}
    # use try and except to check if table already exist or not
    try:
        # open the arp_table.json file for reading only. 
        with open(Location_of_local_arp_table, "r") as f:
            # to read an parse Json data 
            save_arp_table = json.load(f)
            # use copy() to create a separate copy of  dictionary 
            arp_table = save_arp_table.copy()
    # if file doesnt occures create it
    except:
        # call function that generate the arp table
        generation_of_arp_table = generate_arp_table()
        arp_table = generation_of_arp_table.copy()
    # writing arp table into local file
    write_arp_table(arp_table, Location_of_local_arp_table)
    return arp_table

# copies the arp table to a global function for other functions in the ids to use
def configure_a_create_global_table_for_arp(arp_table):
    #loop over each key of dict arp_table 
    for arp_ip in arp_table:
        # save result in global dictionary 
        # key is ip,  value is the mac
        create_global_table_for_arp[arp_ip] = arp_table[arp_ip]

# Write the arp taonble in a local file 
# save dictioanry of key:ip value: mac in a json file
def write_arp_table(arp_table, file_name):
        # open file to write 
        with open(file_name, "w") as f:
            # put arp_table dictonary result in the file
            json.dump(arp_table, f)



# generate arp table by sending packets to all ips in the network
# This is to get Mac address for each user based on range of all possible ips
def generate_arp_table():
    # To save result of ARP responce as Key:IP and Value: Mac
    result = {}

    # This is used to put a condition on packet being sent
    PACKETS_SENT = 10

    # Max of all possible Ips where 255 is the broadcast
    IP_MAX_RANGE= 254

    #scp is a secure network protocol that allow the secure copy of file 
    # conf is used for configuration of system
    # route is used for network configuration
    # IP address that used as destination to send arp request
    default_gateway_IP = scp.conf.route.route("0.0.0.0")[2]

    # rsplit function is used to split string from right based on delimiter which is dot in this case
    #Now split IP to get [xxx.xxx.xxx , xxx] for exampl 192.168.1.2 [192.168.1, 2]
    split_default_gateway_ip = default_gateway_IP.rsplit(".", 1)


    # array for packet
    array_for_packet = []

    # loop over all ips on local network
    for i in range(1, IP_MAX_RANGE + 1):
        # get the first 3 octet of the ip address and add to it the last one 
        # this allow to move on all ip on the local
        ip = split_default_gateway_ip[0] + "." + str(i)

        # Ether used to generate Ethernet frame with dst address identify device that will recieve this frame
        # the Ether fram is a broadcast one to all detination 
        # used to resolve Ip to its mac address 
        # This create a complete packet that can be send over network
        

        arp_request_broadcast = scp.Ether(dst="ff:ff:ff:ff:ff:ff") / scp.ARP(pdst=ip)
        
        # this save all packets to have a packet for every ip in the local network
        array_for_packet.append(arp_request_broadcast)

        # this condition is used to send a batch of packet (reduce overhead)
        # also in this case need to handle when number of ip range remains is less than the condition on packet
        if (
            len(array_for_packet) >= PACKETS_SENT
            or IP_MAX_RANGE - i < PACKETS_SENT
        ):
            # srp is a function used to send packets over data link layer
            # array_for_packet contain packets that need to be sent which are broadcast with an ip in order to get its Mac
            # timeout is the time to waite for responce 
            # verbose if it is True will print detial information about packet
            recieved = scp.srp(array_for_packet, timeout=0.5, verbose=False)[0]

            # to remove all packets 
            array_for_packet.clear()

            for rec in recieved:
                # index one represent the recieved packet
                # here it is the responce of ARP request
                # getlayer resutrn the specified layer which is here ARP, and resturn none otherwise
                # psrc: to get source IP address of the ARP response
                #hwsrc: to get mac address of ARP responce
                ip = rec[1].getlayer(scp.ARP).psrc
                mac = rec[1].getlayer(scp.ARP).hwsrc
                # save result in the dictionary where the MAC address  (value) associated with a specific IP (key)
                result[ip] = mac
           # Add the local machine's IP and MAC address to the result
    local_ip = scp.get_if_addr(scp.conf.iface)
    local_mac = scp.get_if_hwaddr(scp.conf.iface)
    result[local_ip] = local_mac

    return result

# This function will update arp table every 30 sec
# Thread scheduling where operating system use scheduling to manage how thread  allocate CPU time
# using sleep function to pause thread for a time 
def update_arp_table():
       while True:
        time.sleep(30)
        # call function that generate the arp table
        updated_arp_table = generate_arp_table()

        while True:
            # if number of arp spoof packet is not zero this will stop updating table
            # to prevent update when a spoof arp attack occurs 
            if number_arp_spoof_packet == 0:
                # update globale arp table variable 
                configure_a_create_global_table_for_arp(updated_arp_table)
                # write changes on location file
                write_arp_table(create_global_table_for_arp, Location_of_local_arp_table)
                break
    
            time.sleep(5)

# This to create a new thread that is responsible to execute the function (update_arp_table) in parallel with the main program
update_arp_table_thread = Thread(target=update_arp_table)