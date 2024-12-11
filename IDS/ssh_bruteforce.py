#reem chaaban

from scapy.all import sniff, TCP, IP  #capture, process network packets w/ TCP and IP headers
from collections import deque, defaultdict  # deque for queued timestamps, defaultdict for tracking attempts
import time
from main_config_file import log_to_file, log_error, read_file, get_variable  # for error handling, logging, etc.

#initialize empty dictionary mapping IP address to list of SSH attempts to track logs
ssh_attempt_tracker = defaultdict(lambda: deque())  # tracks timestamps of attempts for each source IP
last_alert_time = {}  # tracks the last alert time for each source IP2

RULES_FILE = "rules.json"  # custom JSON file with detection rules

#processes SSH packets to detect brute force attempts
def ssh_bruteforce_processor(packet):
    global last_alert_time #change last_alert_time based on timestamp
    try:
        if not (packet.haslayer(TCP) and packet.haslayer(IP) and packet[TCP].dport == 22):
            return #if TCP, IP layers missing & destination port is not port 22 (SSH), exit

        #extract source, destination IPs (scapy)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        rules = read_file(RULES_FILE) #load rules.json file containing custom rule to detect
        threshold, time_window = get_variable(rules, "tcp", "ssh_brute")  # extract threshold and time window from SSH brute force rule (identified by "tcp", "ssh_brute"

        if not threshold or not time_window:
            log_error("SSH brute force detection: Invalid rules :(")
            return #if threshold and time window are missing from the rules.json file, exit

        current_time = time.time()  #get current time

        ssh_attempt_tracker[src_ip].append(current_time) #append current time w/ source IP to created timestamp list

        while ssh_attempt_tracker[src_ip] and ssh_attempt_tracker[src_ip][0] < current_time - time_window:
            ssh_attempt_tracker[src_ip].popleft() #if last alert associated with source in timestamp list is older than the time window (e.g., 30 seconds), remove it

	#check on source IP only, as brute force attacks originate from 1 attacker normally with multiple attempts
        if len(ssh_attempt_tracker[src_ip]) >= threshold:
        #if the number of attempts > specified threshold (5 attempts in 30 seconds here), log alert
            if src_ip not in last_alert_time or current_time - last_alert_time[src_ip] >= time_window:
                timestamp = time.strftime("%m/%d-%H:%M:%S.%f", time.localtime(current_time))[:-3]
                alert_message = ( #format similar to SNORT
                    f"{timestamp} [**] SSH brute force attack detected! [**] "
                    f"{{TCP}} {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport}"
                )
                log_to_file(alert_message)  # record log in log.txt
                print(alert_message)  # print log in the terminal
                last_alert_time[src_ip] = current_time  # update last alert time for this source IP

    except Exception as e:
        log_error(f"SSH Brute Force Detection Error: {e}")


#SNORT rule that's being compared: tcp any any -> $HOME_NET 22 (msg:"SSH brute force attempt detected!"; flow:to_server, established; content:"ssh"; nocase; threshold: type both, track by_src, count 5, seconds 30; metadata: service http; sid:1000002; rev:1;)

# we are avoiding multiple alerts from a singular attack in one time window to ensure better consistency with the configuration of snort so that evaluation is fair


