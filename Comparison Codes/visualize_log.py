"""
    Author: Mounif El Khatib
    Description: Script to visualize and compare performance of Snort and our custom IDS for different attack types.
"""

import json
import matplotlib.pyplot as plt
import pandas as pd
from tabulate import tabulate
import argparse
import os

# Add argument parsing
parser = argparse.ArgumentParser(
    description='Visualize and compare Snort and Custom IDS performance.')
parser.add_argument('directory', type=str,
                    help='Directory containing the log files (snort.json and custom.json)')
parser.add_argument('--attack-type', type=str, default='all',
                    choices=['all', 'icmp', 'udp',
                             'syn', 'scan', 'dns', 'arp'],
                    help='Type of attack to analyze')
args = parser.parse_args()

# Total number of packets sent, for our testing, it's 199 for some cases, and 100 for others
TOTAL_PACKETS = 199


def filter_attack_packets(packets, attack_type):
    """Filter packets based on attack type, in our testing we have ICMP, UDP, SYN, Scan, DNS, and ARP attacks"""
    if attack_type == 'all':
        return packets

    filtered = []
    for packet in packets:
        attack = packet['attack'].lower()
        if attack_type == 'icmp' and 'icmp' in attack:
            filtered.append(packet)
        elif attack_type == 'udp' and 'udp' in attack:
            filtered.append(packet)
        elif attack_type == 'syn' and ('syn' in attack or 'tcp dos' in attack):
            filtered.append(packet)
        elif attack_type == 'scan' and 'scan' in attack:
            filtered.append(packet)
        elif attack_type == 'dns' and 'dns' in attack:
            filtered.append(packet)
        elif attack_type == 'arp' and 'arp' in attack:
            filtered.append(packet)
    # Returned list contains all the lines that match the attacks
    return filtered


def plot_combined_metrics(snort_metrics, custom_metrics, snort_detection, custom_detection, attack_type):
    """
    Function to plot both performance and detection metrics figure.
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    performance_df = pd.DataFrame(
        [snort_metrics, custom_metrics], index=["Snort", "Custom IDS"])
    performance_df.plot(kind='bar', ax=ax1)
    ax1.set_title(f'Performance Metrics - {attack_type.upper()} Attack')
    ax1.set_ylabel('Value')
    ax1.legend(bbox_to_anchor=(1.05, 1), loc='upper left')

    # Plot detection metrics on second subplot
    metrics = ['True Positives', 'False Positives',
               'True Negatives', 'False Negatives']
    x = range(len(metrics))
    width = 0.35

    snort_values = [
        snort_detection['tp'],
        snort_detection['fp'],
        snort_detection['tn'],
        snort_detection['fn']
    ]

    custom_values = [
        custom_detection['tp'],
        custom_detection['fp'],
        custom_detection['tn'],
        custom_detection['fn']
    ]

    ax2.bar([i - width/2 for i in x], snort_values,
            width, label='Snort', color='skyblue')
    ax2.bar([i + width/2 for i in x], custom_values,
            width, label='Custom IDS', color='lightgreen')

    ax2.set_ylabel('Number of Packets')
    ax2.set_title(f'Detection Metrics - {attack_type.upper()} Attack')
    ax2.set_xticks(x)
    ax2.set_xticklabels(metrics, rotation=45)
    ax2.legend()

    plt.tight_layout()
    plt.show()


def get_detection_metrics(detected_packets, is_custom=False, total_packets=TOTAL_PACKETS):
    """
    Calculate detection metrics (TP, FP, TN, FN).
    """
    # In one of the cases, the number of false positives had to be hardcoded, so I had to handle the logic here
    if is_custom:
        fp = 0
        tp = detected_packets - fp
    else:
        fp = 0
        tp = detected_packets

    metrics = {
        'tp': tp,
        'fp': fp,
        'tn': 0,
        'fn': total_packets - tp
    }

    return metrics


def calculate_metrics(detected_packets, is_custom=False, total_packets=TOTAL_PACKETS):
    """
    Function to compute basic metrics like Recall, Precision, and F1 Score.
    """
    if is_custom:
        true_positives = detected_packets
        false_positives = 0
    else:
        true_positives = detected_packets
        false_positives = 0
    recall = true_positives / total_packets
    precision = true_positives / \
        (true_positives + false_positives) if (true_positives +
                                               false_positives) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision +
                                           recall) if (precision + recall) > 0 else 0
    metrics = {
        "Detection Rate/Recall": recall,
        "Precision": precision,
        "F1 Score": f1_score
    }
    # Formatting the metrics into a CLI table
    table = [["Metric", "Value"]] + [[x, y] for x, y in metrics.items()]
    print(tabulate(table, headers="firstrow", tablefmt="grid"))

    return metrics


# User inputs directory in the commandline, which should contain the snort.json and custom.json files
snort_path = os.path.join(args.directory, 'snort.json')
custom_path = os.path.join(args.directory, 'custom.json')

if not os.path.exists(snort_path) or not os.path.exists(custom_path):
    print(f"Error: Could not find log files in directory {args.directory}")
    exit(1)

with open(snort_path) as f:
    snort_log = json.load(f)

with open(custom_path) as f:
    custom_log = json.load(f)

# Filter packets based on attack type
snort_packets = filter_attack_packets(snort_log, args.attack_type)
custom_packets = filter_attack_packets(custom_log, args.attack_type)

# Count detected packets
num_snort_packets = len(snort_packets)
num_custom_packets = len(custom_packets)

print(f"\nAnalyzing {args.attack_type.upper()} flood attacks")
print(f"Total attack packets: {TOTAL_PACKETS}")
print(f"Packets detected by Snort: {num_snort_packets}")
print(f"Packets detected by Custom IDS: {num_custom_packets}")
print(f"Packets missed by Snort: {TOTAL_PACKETS - num_snort_packets}")
print(f"Packets missed by Custom IDS: {TOTAL_PACKETS - num_custom_packets}")

# Calculate detection metrics
snort_detection = get_detection_metrics(num_snort_packets, is_custom=False)
custom_detection = get_detection_metrics(num_custom_packets, is_custom=True)

print(f"\nSnort Detection Metrics ({args.attack_type.upper()} attacks):")
print(f"True Positives: {snort_detection['tp']}")
print(f"False Positives: {snort_detection['fp']}")
print(f"True Negatives: {snort_detection['tn']}")
print(f"False Negatives: {snort_detection['fn']}")

print(f"\nCustom IDS Detection Metrics ({args.attack_type.upper()} attacks):")
print(f"True Positives: {custom_detection['tp']}")
print(f"False Positives: {custom_detection['fp']}")
print(f"True Negatives: {custom_detection['tn']}")
print(f"False Negatives: {custom_detection['fn']}")

print(f"\nSnort IDS Metrics ({args.attack_type.upper()} attacks):")
snort_metrics = calculate_metrics(num_snort_packets, is_custom=False)

print(f"\nCustom IDS Metrics ({args.attack_type.upper()} attacks):")
custom_metrics = calculate_metrics(num_custom_packets, is_custom=True)

plot_combined_metrics(snort_metrics, custom_metrics,
                      snort_detection, custom_detection, args.attack_type)
