"""
    Author: Mounif El Khatib
    Description: This file analyzes ICMP and SYN flood attacks detected by a custom IDS and Snort, it's the same as visualize_log.py but for ICMP and SYN flood attacks being done at once.
"""

import matplotlib.pyplot as plt
import pandas as pd
from tabulate import tabulate

TOTAL_PACKETS = 199  # Total attack packets sent


def parse_logs(log_path, alerts_path):
    """Parse logs to count ICMP and SYN flood detections"""
    log_detections = {
        'icmp': 0,
        'syn': 0
    }
    snort_detections = {
        'icmp': 0,
        'syn': 0
    }
    # Parse custom IDS log
    with open(log_path) as f:
        for line in f:
            if 'ICMP Flood detected' in line:
                log_detections['icmp'] += 1
            elif 'SYN Flood Detected' in line:
                log_detections['syn'] += 1

    # Parse Snort alerts containing ICMP Flood or Possible TCP DoS
    with open(alerts_path) as f:
        for line in f:
            if 'ICMP Flood' in line:
                snort_detections['icmp'] += 1
            elif 'Possible TCP DoS' in line:
                snort_detections['syn'] += 1

    return log_detections, snort_detections


def calculate_metrics(detected, total=TOTAL_PACKETS):
    """Calculate detection metrics"""
    recall = detected / total
    precision = 1.0 if detected > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision +
                                           recall) if (precision + recall) > 0 else 0
    return {
        "Detection Rate/Recall": recall,
        "Precision": precision,
        "F1 Score": f1_score
    }


def print_metrics(metrics, attack_type):
    """Print metrics in tabulated format"""
    table = [["Metric", "Value"]] + [[x, y] for x, y in metrics.items()]
    print(f"\nMetrics for {attack_type} flood attacks:")
    print(tabulate(table, headers="firstrow", tablefmt="grid"))


def plot_metrics(snort_metrics, custom_metrics, attack_type):
    """Plot metrics comparison"""
    df = pd.DataFrame([snort_metrics, custom_metrics],
                      index=["Snort", "Custom IDS"])
    ax = df.plot(kind='bar', figsize=(10, 5))
    plt.title(f'Performance Metrics - {attack_type} Flood Attack')
    plt.xlabel('IDS')
    plt.ylabel('Value')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    log_path = "icmp_syn/log.txt"
    alerts_path = "icmp_syn/alerts.txt"

    # Parsing log files
    log_detections, snort_detections = parse_logs(log_path, alerts_path)

    # ICMP Flood metrics
    print(f"\nICMP Flood Analysis:")
    print(f"Custom IDS detections: {log_detections['icmp']}")
    print(f"Snort detections: {snort_detections['icmp']}")

    # Computing and displaying metrics for ICMP packets
    icmp_custom_metrics = calculate_metrics(log_detections['icmp'])
    icmp_snort_metrics = calculate_metrics(snort_detections['icmp'])

    print_metrics(icmp_custom_metrics, "ICMP")
    print_metrics(icmp_snort_metrics, "ICMP (Snort)")
    plot_metrics(icmp_snort_metrics, icmp_custom_metrics, "ICMP")

    # SYN Flood metrics
    print(f"\nSYN Flood Analysis:")
    print(f"Custom IDS detections: {log_detections['syn']}")
    print(f"Snort detections: {snort_detections['syn']}")

    # Computing and displaying SYN flood metrics
    syn_custom_metrics = calculate_metrics(log_detections['syn'])
    syn_snort_metrics = calculate_metrics(snort_detections['syn'])

    print_metrics(syn_custom_metrics, "SYN")
    print_metrics(syn_snort_metrics, "SYN (Snort)")
    plot_metrics(syn_snort_metrics, syn_custom_metrics, "SYN")
