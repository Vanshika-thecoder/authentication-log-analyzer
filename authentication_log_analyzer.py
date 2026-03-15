import re
import pandas as pd
from collections import defaultdict

print("=== Login Anomaly Detection System ===\n")

logs = [
    "Failed login from 192.168.1.10",
    "Failed login from 192.168.1.10",
    "Failed login from 192.168.1.10",
    "Successful login from 192.168.1.5",
    "Failed login from 192.168.1.22",
    "Failed login from 192.168.1.22",
    "Successful login from 192.168.1.8",
    "Failed login from 10.0.0.5",
    "Failed login from 10.0.0.5",
    "Failed login from 10.0.0.5",
    "Failed login from 10.0.0.5"
]

df = pd.DataFrame(logs, columns=["log"])

print("Sample Log Data:\n")
print(df)

FAILED_PATTERN = r"Failed login from (\d+\.\d+\.\d+\.\d+)"

failed_attempts = defaultdict(int)

for entry in logs:
    
    match = re.search(FAILED_PATTERN, entry)
    
    if match:
        ip = match.group(1)
        failed_attempts[ip] += 1
THRESHOLD = 3

suspicious_ips = []

for ip, attempts in failed_attempts.items():
    
    if attempts >= THRESHOLD:
        suspicious_ips.append((ip, attempts))

print("\n=== Security Analysis Report ===\n")

if suspicious_ips:
    
    for ip, attempts in suspicious_ips:
        
        print(f"⚠ Suspicious activity detected")
        print(f"IP Address: {ip}")
        print(f"Failed Login Attempts: {attempts}")
        print("Possible brute-force attack\n")

else:
    
    print("No suspicious login activity detected")

summary = pd.DataFrame(
    failed_attempts.items(),
    columns=["IP Address", "Failed Attempts"]
)

print("Failed Login Summary:\n")
print(summary)

summary.to_csv("security_report.csv", index=False)

print("\nSecurity report saved as: security_report.csv")
