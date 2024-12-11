"""
    Author: Mounif El Khatib
    Description: Parses Snort output into a JSON format
"""
import re
from datetime import datetime
import argparse
import json


def parse_alert_line(line):
    # Generic pattern that matches both timestamping formats and all protocols
    patterns = [
        r'(?:(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6})|(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}))\s+'
        r'(?:\[\*\*\]\s+\[\d+:\d+:\d+\]\s+)?(.*?)\s+'
        r'(?:\[\*\*\]\s+\[Priority:\s+\d+\]\s+)?'
        r'{(\w+)}\s+'
        r'(\d+\.\d+\.\d+\.\d+)(?::(\d+))?\s+'
        r'(?:->|-->)\s+'
        r'(\d+\.\d+\.\d+\.\d+)(?::(\d+))?'
    ]

    for pattern in patterns:
        match = re.match(pattern, line)
        if match:
            # Extract all groups
            groups = match.groups()
            # Determine which timestamp format was matched and parse accordingly
            if groups[0]:
                timestamp = groups[0]
                datetime_obj = datetime.strptime(
                    timestamp, "%m/%d-%H:%M:%S.%f")
                formatted_datetime = datetime_obj.replace(
                    year=2024).strftime("%Y-%m-%dT%H:%M:%S")
                attack = groups[2]
                protocol = groups[3]
                src_ip = groups[4]
                src_port = groups[5] or "N/A"
                dst_ip = groups[6]
                dst_port = groups[7] or "N/A"
            else:  # YYYY-mm-dd HH:MM:SS format
                formatted_datetime = datetime.strptime(
                    groups[1], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%S")
                attack = groups[2]
                protocol = groups[3]
                src_ip = groups[4]
                src_port = groups[5] or "N/A"
                dst_ip = groups[6]
                dst_port = groups[7] or "N/A"

            return {
                "datetime": formatted_datetime,
                "attack": attack.strip(),
                "protocol": protocol,
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port
            }

    print(f"Warning: Unable to parse line: {line.strip()}")
    return None


if __name__ == "__main__":
    # Getting options from the commandline
    parser = argparse.ArgumentParser(
        description='Parse Snort alerts to JSON format')
    parser.add_argument('input',
                        help='Input alerts file path')
    parser.add_argument('-o', '--output',
                        help='Output JSON file path')
    args = parser.parse_args()

    # Process the input file and store results
    alerts = []
    try:
        with open(args.input, 'r') as infile:
            for line in infile:
                alert = parse_alert_line(line.strip())
                if alert:
                    alerts.append(alert)

        # Write the results to a JSON file
        with open(args.output, 'w') as outfile:
            json.dump(alerts, outfile, indent=4)

        print(f"Successfully processed {len(alerts)} alerts")
        print(f"Output written to: {args.output}")

    except FileNotFoundError:
        print(f"Error: Input file '{args.input}' not found")
    except Exception as e:
        print(f"Error: {str(e)}")
