import csv
import os
import urllib.parse
import sys

input_file = "OWASP_CRS_PROJECT/GoTestWAF/gotestwaf_results_before_rules.csv"
output_file = "benchmark/datasets/GoTestWAF/gotestwaf_xss.csv"

os.makedirs(os.path.dirname(output_file), exist_ok=True)

# Increase CSV structural field limit to handle very large payloads
csv.field_size_limit(sys.maxsize)

xss_payloads = []

if not os.path.exists(input_file):
    print(f"Error: Input file {input_file} not found.")
    sys.exit(1)

with open(input_file, 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    for row in reader:
        # GoTestWAF CSV format has Payload at index 0, TestCase at index 6
        if len(row) > 6 and 'xss' in row[6].lower():
            # URL decode the payload to match Mereani format
            payload = urllib.parse.unquote(row[0])
            xss_payloads.append(payload)

with open(output_file, 'w', encoding='utf-8', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["Payload", "Label"])
    for payload in xss_payloads:
        writer.writerow([payload, "Malicious"])

print(f"Extracted {len(xss_payloads)} XSS payloads to {output_file}")
