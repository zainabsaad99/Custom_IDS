#reem chaaban

from scapy.all import TCP, Raw, IP #capture, process network packets w/ TCP, IP  headers, and raw data
from collections import deque, defaultdict #deque manages queued timestamps; defaultdict is used for tracking src, dest IPs 
import time
from main_config_file import log_to_file, log_error, read_file, get_variable #from main_config_file.py for error handling, logging, etc.

#initialize empty dictionary mapping IP address to list of HTTP requests to track logs
http_request_tracker = defaultdict(list)
last_alert_time = {}  #stores last timestamp where alert was generated (due to HTTP flood detection); mapped to src/dest IP address

RULES_FILE = "rules.json" #custom JSON file with detection rules

#store source-destination pairs of HTTP requests to keep track
store_httpflood_src = defaultdict(lambda: deque()) 
store_httpflood_dest = defaultdict(lambda: deque())

def httpflood_processor(packet): #packet sniffed by scapy -> call this function
    global last_alert_time #change last_alert_time based on timestamp
    try:
        if not (packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP)): #if TCP, IP, or raw data missing, exit
            return

        src_ip = packet[IP].src #extract source IP address from IP
        dst_ip = packet[IP].dst #extract destination IP address from IP 
        payload = packet[Raw].load.decode("utf-8", errors="ignore") #extract raw data & decode using UTF-8

        if "GET / HTTP/1.1" not in payload: #if HTTP GET request is absent in a packet's raw data, exit
            return

        rules = read_file(RULES_FILE) #load rules.json file containing custom rule to detect
        threshold, time_window = get_variable(rules, "tcp", "flood") #extract threshold (# of events that qualify to generate log) & time_window, which we have defined as seconds in rules.json (time period to count requests in)

        if not threshold or not time_window:
            log_error("HTTP flood detection: Invalid rules :(") #cannot extract/detect seconds & threshold
            return

        current_time = time.time() #using time library, get current time (keep track of when requests are being logged)
        src_dest_pair = f"{src_ip},{dst_ip}" #to keep track of source-destination pairs being logged

	#associate the current time with source-destination pair (logging)
        store_httpflood_src[src_dest_pair].append(current_time)
        store_httpflood_dest[dst_ip].append(current_time)
        
	#if the stored source-destination pair's logging time is older than the time window, remove it (make space for newer alerts)
        while store_httpflood_src[src_dest_pair] and store_httpflood_src[src_dest_pair][0] < current_time - time_window:
            store_httpflood_src[src_dest_pair].popleft() 

        while store_httpflood_dest[dst_ip] and store_httpflood_dest[dst_ip][0] < current_time - time_window:
            store_httpflood_dest[dst_ip].popleft()

	# if # of requests from source (attacker) to destination (victim) > threshold, check how much time has passed since the last alert was generated. if it's within the time window, generate a log
	
	#check on source IP: HTTP floods from single source
        if len(store_httpflood_src[src_dest_pair]) >= threshold:
            if src_ip not in last_alert_time or current_time - last_alert_time[src_ip] >= time_window:
                timestamp = time.strftime("%m/%d-%H:%M:%S.%f", time.localtime(current_time))[:-3]
                alert_message = (
                    f"{timestamp} [**] HTTP flood attack detected! [**] "
                    f"[Priority: 0] {{TCP}} {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport}"
                )
                log_to_file(alert_message)  # record log in log.txt
                print(alert_message)  # print log in  terminal
                last_alert_time[src_ip] = current_time  # update last alert time for this src IP

	#check on destination IP: HTTP floods from multiple sources to single victim
        elif len(store_httpflood_dest[dst_ip]) >= threshold:
            if len(store_httpflood_src[src_dest_pair]) == 1 and len(store_httpflood_dest[dst_ip]) > 1:
                return  #if an alert has been generated in the last time window, exit

            if dst_ip not in last_alert_time or current_time - last_alert_time[dst_ip] >= time_window: #if no alert for HTTP flood event in the same time window, generate an alert
                timestamp = time.strftime("%m/%d-%H:%M:%S.%f", time.localtime(current_time))[:-3]
                alert_message = (
                    f"{timestamp} [**] HTTP flood attack detected! [**] "
                    f"{{TCP}} {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport}"
                )
                log_to_file(alert_message)  # record log in log.txt
                print(alert_message)  # print log in  terminal
                last_alert_time[dst_ip] = current_time  # update last alert time for this dest IP
    
    except Exception as e:
        log_error(f"HTTP flood detection error: {e}")
        
        
        
# SNORT rule that's being compared: tcp any any -> $HOME_NET 80 (msg:"HTTP flood attack detected!"; flow:to_server; flags:A+; content:"GET / HTTP/1.1"; nocase; threshold: type both, track by_src, count 40, seconds 10; metadata: service http; sid:1000003; rev:1;)

# we are avoiding multiple alerts from a singular attack in one time window to ensure better consistency with the configuration of snort so that evaluation is fair

# 
