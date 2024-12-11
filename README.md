# Performance of Hybrid Motoring IDS
## Introduction
An Intrusion Detection System (IDS) in the network
plays an important role in identifying attacks by monitoring
network activities to detect malicious behavior. Moreover, this
tool relies on passive monitoring of sequence of events which
caused by an intruder such as snort. However, there are attacks
in which passive monitoring has a limitation, since no change
occurs in the sequence of events such as ARP spoofing , leading
to ineffective passive monitoring. In order to address this, an
active probe is sent to determine the change that occurs. In this
paper, an IDS is proposed that detects ARP spoofing, through this
paper an analysis will be performed to check the performance
of the IDS that is a hybrid motoring comparing to snort which
is a passive monitoring

#### YouTube link to demo
https://youtu.be/LHKV3YwuDPw?si=sBt38L_pbfmXhqfu

## Rule File
This file contains rule where it should be updated based on your network IP
## Attacks and Required Inputs

## Description
This project simulates several types of network attacks for educational and research purposes, including DNS Amplification, ARP Spoofing, SYN Flood, UDP Flood, ICMP Flood, and Port Scanning. Each attack is implemented in a separate script, and the required inputs for each attack are described below.

### 1. **DNS Amplification Attack**
- **Description**: Simulates a DNS amplification attack by sending spoofed DNS queries that result in large responses to a victim's IP address.
- **Inputs**:
  - **Target IP**: The IP address of the victim.
  - **query_option**: To choose between ["dane.verisignlabs.com", "sigok.verteiltesysteme.net"]

### 2. **ARP Spoofing Attack**

- **Description**: Sends falsified ARP messages to the local network, associating the attacker's MAC address with the IP address of another device (victim) and gateway 
- **Inputs:**
  - **Target IP:** The IP address of the victim.
  - **Gateway IP:** The IP address of the default gateway.
  

### 3. **SYN Flood Attack**

- **Description:** Floods a target with TCP SYN packets, attempting to exhaust its resources by creating half-open connections.
- **Inputs:**
        - **Target IP:** The IP address of the victim.
        - **Target Port:** The port on which to send the SYN packets (e.g., 80, 443).

### 4. **UDP Flood Attack**

- **Description:** Sends a high volume of UDP packets to overwhelm the target's network, causing resource exhaustion.
- **Inputs:**
        - **Target IP:** The IP address of the victim.


### 5. **ICMP Flood Attack**

- **Description:** Sends a large number of ICMP Echo Request packets (ping) to overwhelm the target's network or host.
- **Inputs:**
  - **Target IP:** The IP address of the victim.
 
### 6. **HTTP Flood Attack**
- **Description:** Sends a large number of HTTP GET request packets to overwhelm the target's network or host and cause denial-of-service for legitimate requests.
- **Inputs:**
  - **Target IP**: Specify the IP address of the target machine
  - **Port #**: Specify the target port, or type 'http' to select port 80
 
### 7. **SSH Brute Attack**
- **Description** The attack machine references a list of username-password combinations and repeatedly attempts (automated to be quick) to log in and gain access to the remote target server.
- **Inputs**
  - **Target IP**: Specify the IP address of the target machine
  - **SSH username**: Enter the username of the server being targeted
  - **Password list directory**: Specify the directory in the attacker machine that contains the list of passwords to be referenced. I found a "10k most common" passwords list on GitHub and used it. It is included in this repository as "pass.txt".
      

## Repository Contents
### Files
- **README.md**: Overview of the project.
- **Attack_Folder**: contain all attack code to test IDS
- **IDS**: contain implementation for hybrid motoring IDS


## Usage
To run the IDS:
```bash
sudo python3 path_to_file/IDS.py

To run attacks:
sudo python3 path_to_file/file_name.py

