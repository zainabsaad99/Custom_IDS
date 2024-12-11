"""
    Author: Mounif El Khatib
    Description: This script analyzes ARP packets, it computes the same metrics as visualize_log.py but for ARP packets.
"""

import matplotlib.pyplot as plt
import pandas as pd
from tabulate import tabulate

# Hardcoded number of packets, 200 in total, half of which are gateway attacks and the other attacks
GATEWAY_ARP_PACKETS = 100
VICTIM_ARP_PACKETS = 100


def parse_log_file(log_file):
    """Parse log file and count attack occurrences for gateway and victim"""
    # Gateway attacks counter
    gateway_attacks = 0
    # Victim attacks counter
    victim_attacks = 0
    with open(log_file, 'r') as f:
        for line in f:
            if "ARP Spoofing" in line:
                # Counting packets is based on the MAC addresses
                if "c8:3a:35:33:ef:20" in line:
                    gateway_attacks += 1
                elif "08:00:27:d1:97:bd" in line:
                    victim_attacks += 1
    return gateway_attacks, victim_attacks


def calculate_metrics(detected_packets, total_packets):
    """Calculating detection metrics, these are the same as in visualize_log.py"""
    recall = detected_packets / total_packets
    precision = 1.0 if detected_packets > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision +
                                           recall) if (precision + recall) > 0 else 0

    metrics = {
        "Detection Rate/Recall": recall,
        "Precision": precision,
        "F1 Score": f1_score
    }
    return metrics


def get_detection_metrics(detected_packets, total_packets):
    """Calculate TP, FP, TN, FN"""
    metrics = {
        'tp': detected_packets,
        'fp': 0,
        'tn': 0,
        'fn': total_packets - detected_packets
    }
    return metrics


def plot_metrics(attack_type, detection_metrics, performance_metrics):
    """Plot detection and performance metrics"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    # Plot performance metrics
    pd.DataFrame([performance_metrics], index=[
                 ""]).plot(kind='bar', ax=ax1)
    ax1.set_title(f'Performance Metrics - {attack_type} Attack')
    ax1.set_ylabel('Value')
    ax1.legend(bbox_to_anchor=(1.05, 1), loc='upper left')

    # Plot detection metrics
    metrics = ['True Positives', 'False Positives',
               'True Negatives', 'False Negatives']
    values = [
        detection_metrics['tp'],
        detection_metrics['fp'],
        detection_metrics['tn'],
        detection_metrics['fn']
    ]

    ax2.bar(metrics, values)
    ax2.set_ylabel('Number of Packets')
    ax2.set_title(f'Detection Metrics - {attack_type} Attack')
    ax2.tick_params(axis='x', rotation=45)

    plt.tight_layout()
    return fig


def main():
    log_file = "ARP/log.txt"

    # Parse log file for ARP attacks
    gateway_detected, victim_detected = parse_log_file(log_file)

    # Calculate metrics for Gateway ARP spoofing
    print("\nGateway ARP Spoofing Attack Analysis:")
    print(f"Total attack packets: {GATEWAY_ARP_PACKETS}")
    print(f"Detected packets: {gateway_detected}")
    print(f"Missed packets: {GATEWAY_ARP_PACKETS - gateway_detected}")

    gateway_detection = get_detection_metrics(
        gateway_detected, GATEWAY_ARP_PACKETS)
    gateway_metrics = calculate_metrics(gateway_detected, GATEWAY_ARP_PACKETS)

    # Calculate metrics for Victim ARP spoofing
    print("\nVictim ARP Spoofing Attack Analysis:")
    print(f"Total attack packets: {VICTIM_ARP_PACKETS}")
    print(f"Detected packets: {victim_detected}")
    print(f"Missed packets: {VICTIM_ARP_PACKETS - victim_detected}")

    victim_detection = get_detection_metrics(
        victim_detected, VICTIM_ARP_PACKETS)
    victim_metrics = calculate_metrics(victim_detected, VICTIM_ARP_PACKETS)

    # Print detection metrics for both
    print("\nGateway ARP Spoofing Detection Metrics:")
    print(f"True Positives: {gateway_detection['tp']}")
    print(f"False Positives: {gateway_detection['fp']}")
    print(f"True Negatives: {gateway_detection['tn']}")
    print(f"False Negatives: {gateway_detection['fn']}")

    print("\nVictim ARP Spoofing Detection Metrics:")
    print(f"True Positives: {victim_detection['tp']}")
    print(f"False Positives: {victim_detection['fp']}")
    print(f"True Negatives: {victim_detection['tn']}")
    print(f"False Negatives: {victim_detection['fn']}")

    # Print performance metrics for both
    print("\nGateway ARP Spoofing Performance Metrics:")
    gateway_table = [["Metric", "Value"]] + [[x, y]
                                             for x, y in gateway_metrics.items()]
    print(tabulate(gateway_table, headers="firstrow", tablefmt="grid"))

    print("\nVictim ARP Spoofing Performance Metrics:")
    victim_table = [["Metric", "Value"]] + [[x, y]
                                            for x, y in victim_metrics.items()]
    print(tabulate(victim_table, headers="firstrow", tablefmt="grid"))

    # Plot metrics for both
    gateway_plot = plot_metrics(
        "Gateway ARP Spoofing", gateway_detection, gateway_metrics)
    gateway_plot.savefig('gateway_arp_metrics.png')

    victim_plot = plot_metrics(
        "Victim ARP Spoofing", victim_detection, victim_metrics)
    victim_plot.savefig('victim_arp_metrics.png')

    plt.show()


if __name__ == "__main__":
    main()
