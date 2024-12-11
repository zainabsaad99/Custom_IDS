# To run IDS 
#sudo python3 /home/vboxuser/Intrusion_Detection_System/IDS.py
# import libraries 
from scapy.all import sniff
import threading

# import the processor functions 
from syn_flood import synflood_processor
from port_scan import portscan_processor
from udp_flood import udpflood_processor
from icmp_flood import icmpflood_processor
from dns_amplifications import dns_amp_processor
from arp_spoof import  arp_spoof_processor, arp_spoof_detector_thread
from http_floodd import httpflood_processor 
from ssh_bruteforce import ssh_bruteforce_processor
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
    elif protocol == "HTTPFlood":
        sniff(filter="tcp port 80", prn=httpflood_processor, store=0)
    elif protocol == "SSHBruteForce":
        sniff(filter="tcp port 22", prn=ssh_bruteforce_processor, store=0)

if __name__ == "__main__":
    # why thread is used?
    """thread allow us to run parallel processing that handle large volume of traffic
       importance of thread:
        1- Allow to process multiple packet or task simultaneously 
        2- Reduce latency that allow to run faster
        3- Allow analysis of different layers 
        4- It distribute workload across multiple CPU core"""
    
    # start sniffing packet for each attack types 
    syn_flood_thread = threading.Thread(target=sniffing_function, args=("SYNFlood",))
    port_scanning_thread = threading.Thread(target=sniffing_function, args=("PortScan",))
    icmp_flood_thread = threading.Thread(target=sniffing_function, args=("ICMPFlood",))
    udp_flood_thread = threading.Thread(target=sniffing_function, args=("UDPFlood",))
    DNS_amplification_thread= threading.Thread(target=sniffing_function, args=("DNSAmplification",))
    arp_spoofing_thread= threading.Thread(target=sniffing_function, args=("ARPSpoofing",))
    http_flood_thread = threading.Thread(target=sniffing_function, args=("HTTPFlood",))
    ssh_bruteforce_thread = threading.Thread(target=sniffing_function, args=("SSHBruteForce",))

   
    # After thread is ready start them 
    arp_spoof_detector_thread.start()
    syn_flood_thread.start()
    port_scanning_thread.start()
    icmp_flood_thread.start()
    udp_flood_thread.start()
    DNS_amplification_thread.start()
    arp_spoofing_thread.start()
    http_flood_thread.start()
    ssh_bruteforce_thread.start()

    # This is used to make sure that the main program waits for their completion 
    syn_flood_thread.join()
    port_scanning_thread.join()
    icmp_flood_thread.join()
    udp_flood_thread.join()
    DNS_amplification_thread.join()
    arp_spoofing_thread.join()
    http_flood_thread.join()
    ssh_bruteforce_thread.join()
