"""
    Author: Mounif El Khatib
    Description: This code works the same as visualize_logs.py but for http-ssh packets.
"""
import matplotlib.pyplot as plt
import pandas as pd
from tabulate import tabulate

custom_http_flood_file = "logs/http_flood/log.txt"
custom_ssh_brute_force_file = "logs/ssh_bruteforce/log.txt"
snort_http_file = "logs/http_flood/snort_http1"

SSH_TOTAL_PACKETS = 6
HTTP_TOTAL_PACKETS = 18


def count_log_events(file_path):
    """Count number of entries in the custom log file"""
    with open(file_path, 'r') as f:
        return len(f.readlines())


def count_snort_events(file_path):
    """Count number of HTTP entries in Snort log"""
    with open(file_path, 'r') as f:
        return len(f.readlines())


def get_detection_metrics(detected_packets, total_packets):
    """Calculate detection metrics"""
    tp = detected_packets
    fp = 0
    fn = total_packets - tp
    tn = 0

    return {
        'tp': tp,
        'fp': fp,
        'tn': tn,
        'fn': fn
    }


def calculate_metrics(detected_packets, total_packets):
    """Calculate performance metrics (Recall, Precision, F1)"""
    recall = detected_packets / total_packets
    precision = 1.0  # Hard coded precision because false positives are 0
    f1_score = 2 * (precision * recall) / (precision +
                                           recall) if (precision + recall) > 0 else 0

    return {
        "Detection Rate/Recall": recall,
        "Precision": precision,
        "F1 Score": f1_score
    }


def plot_combined_metrics(attack_type, snort_metrics, custom_metrics, snort_detection, custom_detection):
    """Plot comparison metrics for both IDSs"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    # Plot performance metrics
    performance_df = pd.DataFrame(
        [snort_metrics, custom_metrics], index=["Snort", "Custom IDS"])
    performance_df.plot(kind='bar', ax=ax1)
    ax1.set_title(f'Performance Metrics - {attack_type}')
    ax1.set_ylabel('Value')
    ax1.legend(bbox_to_anchor=(1.05, 1), loc='upper left')

    # Plot detection metrics
    metrics = ['True Positives', 'False Positives',
               'True Negatives', 'False Negatives']
    x = range(len(metrics))
    width = 0.35

    snort_values = [snort_detection['tp'], snort_detection['fp'],
                    snort_detection['tn'], snort_detection['fn']]
    custom_values = [custom_detection['tp'], custom_detection['fp'],
                     custom_detection['tn'], custom_detection['fn']]

    ax2.bar([i - width/2 for i in x], snort_values,
            width, label='Snort', color='skyblue')
    ax2.bar([i + width/2 for i in x], custom_values,
            width, label='Custom IDS', color='lightgreen')

    ax2.set_ylabel('Number of Packets')
    ax2.set_title(f'Detection Metrics - {attack_type}')
    ax2.set_xticks(x)
    ax2.set_xticklabels(metrics, rotation=45)
    ax2.legend()

    plt.tight_layout()
    plt.show()


def display_metrics_table(metrics, ids_name, attack_type):
    """Display metrics in a formatted table"""
    print(f"\n{ids_name} {attack_type} Detection Metrics:")
    print(tabulate([[x, y] for x, y in metrics.items()],
                   headers=['Metric', 'Value'],
                   tablefmt='grid'))


# Count detections
custom_http_detections = count_log_events(custom_http_flood_file)
custom_ssh_detections = count_log_events(custom_ssh_brute_force_file)
snort_http_detections = count_snort_events(snort_http_file)
snort_ssh_detections = 3

# HTTP Flood Analysis
print("\nHTTP Flood Analysis:")
print(f"Total HTTP packets: {HTTP_TOTAL_PACKETS}")
print(f"Packets detected by Snort: {snort_http_detections}")
print(f"Packets detected by Custom IDS: {custom_http_detections}")

http_snort_detection = get_detection_metrics(
    snort_http_detections, HTTP_TOTAL_PACKETS)
http_custom_detection = get_detection_metrics(
    custom_http_detections, HTTP_TOTAL_PACKETS)

http_snort_metrics = calculate_metrics(
    snort_http_detections, HTTP_TOTAL_PACKETS)
http_custom_metrics = calculate_metrics(
    custom_http_detections, HTTP_TOTAL_PACKETS)

display_metrics_table(http_snort_metrics, "Snort", "HTTP")
display_metrics_table(http_custom_metrics, "Custom IDS", "HTTP")

plot_combined_metrics('HTTP Flood', http_snort_metrics, http_custom_metrics,
                      http_snort_detection, http_custom_detection)

# SSH Brute Force Analysis
print("\nSSH Brute Force Analysis:")
print(f"Total SSH packets: {SSH_TOTAL_PACKETS}")
print(f"Packets detected by Snort: {snort_ssh_detections}")
print(f"Packets detected by Custom IDS: {custom_ssh_detections}")

ssh_snort_detection = get_detection_metrics(
    snort_ssh_detections, SSH_TOTAL_PACKETS)
ssh_custom_detection = get_detection_metrics(
    custom_ssh_detections, SSH_TOTAL_PACKETS)

ssh_snort_metrics = calculate_metrics(snort_ssh_detections, SSH_TOTAL_PACKETS)
ssh_custom_metrics = calculate_metrics(
    custom_ssh_detections, SSH_TOTAL_PACKETS)

display_metrics_table(ssh_snort_metrics, "Snort", "SSH")
display_metrics_table(ssh_custom_metrics, "Custom IDS", "SSH")

plot_combined_metrics('SSH Brute Force', ssh_snort_metrics, ssh_custom_metrics,
                      ssh_snort_detection, ssh_custom_detection)
