"""Zainab Saad
   ID:202472448"""
# To run IDS 

#sudo python3 /home/vboxuser/IDS/IDS.py
# import libraries 
from scapy.all import sniff
import threading

# import the processor functions 
from syn_flood import synflood_processor
from port_scan import portscan_processor
from udp_flood import udpflood_processor
from icmp_flood import icmpflood_processor
from create_arp_table import configure_local_arp_table
# from test import icmpflood_processor
from dns_amplifications import dns_amp_processor
from arp_spoof import  arp_spoof_processor, arp_spoof_detector_thread
# why sniffing is used?
""" sniff is the process that capture and monitor  packets 
    importance of sniffing:
    1- real-time monitoring 
    2- it is a deep packe inspection that allow to analysis not only header but also the payload
    3- allow analysis of protocols  
"""
# Thi function is used to start sniffing 
def sniffing_function(protocol):
    """
    This function sniff based on the protocol specifies in the main
    """
    if protocol == "SYNFlood":
        sniff(filter="tcp", prn=synflood_processor, store=0)
    elif protocol == "PortScan":
        sniff(filter="tcp", prn=portscan_processor, store=0)
    elif protocol == "ICMPFlood":
        sniff(filter="icmp", prn=icmpflood_processor, store=0)
    elif protocol == "UDPFlood":
        sniff(filter="udp", prn=udpflood_processor, store=0)
    elif protocol == "DNSAmplification":
        sniff(prn=dns_amp_processor, filter="udp port 53", store=0)
    elif protocol == "ARPSpoofing":
        #sniff(filter="arp", prn=arp_spoof_processor, store=False)
        sniff(filter="arp", prn=arp_spoof_processor, store=False)

if __name__ == "__main__":
    # why thread is used?
    """thread allow us to run parallel processing that handle large volume of traffic
       importance of thread:
        1- Allow to process multiple packet or task simultaneously 
        2- Reduce latency that allow to run faster
        3- Allow analysis of different layers 
        4- It distribute workload across multiple CPU core"""
   
    # start sniffing packet for each attack types 
    SYN_Flodd_Thread = threading.Thread(target=sniffing_function, args=("SYNFlood",))
    Port_Scan_Thread = threading.Thread(target=sniffing_function, args=("PortScan",))
    ICMP_Flood_Thread = threading.Thread(target=sniffing_function, args=("ICMPFlood",))
    UDP_Flood_Thread = threading.Thread(target=sniffing_function, args=("UDPFlood",))
    DNS_amplification_thread= threading.Thread(target=sniffing_function, args=("DNSAmplification",))
    ARP_Spoofing_Thread= threading.Thread(target=sniffing_function, args=("ARPSpoofing",))

    # After thread is ready start them 
    arp_spoof_detector_thread.start()
    SYN_Flodd_Thread.start()
    Port_Scan_Thread.start()
    ICMP_Flood_Thread.start()
    UDP_Flood_Thread.start()
    DNS_amplification_thread.start()
    ARP_Spoofing_Thread.start()

    # This is used to make sure that the main program waits for their completion 
    SYN_Flodd_Thread.join()
    Port_Scan_Thread.join()
    ICMP_Flood_Thread.join()
    UDP_Flood_Thread.join()
    DNS_amplification_thread.join()
    ARP_Spoofing_Thread.join()
