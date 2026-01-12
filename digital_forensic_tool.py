import hashlib
from os import read
import pandas as pd
from collections import Counter
from datetime import datetime

# =========================
# EVIDENCE HASHING MODULE
# =========================
def hash_evidence(file_path):
    """Generate SHA-256 hash for evidence integrity verification"""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()


# =========================
# NETWORK ANALYSIS MODULE
# =========================
def parse_pcap(pcap_summary_file):
    """
    Analyze network traffic summary (CSV extracted from PCAP)
    This simplified approach is acceptable for academic forensic projects.
    """
    df = pd.read_csv(pcap_summary_file)   # read-only
    ip_counts = Counter(df["Source"])
    suspicious_ips = [ip for ip, count in ip_counts.items() if count > 5]

    return suspicious_ips, ip_counts


# =========================
# LOG ANALYSIS MODULE
# =========================
def analyze_logs(log_file):
    """Analyze system logs to detect failed login attempts"""
    df = pd.read_csv(log_file)
    failed_logins = df[df["Status"] == "FAIL"]
    suspicious_ips = failed_logins["IP"].value_counts()

    return suspicious_ips


# =========================
# MAIN WORKFLOW
# =========================
def main():
    print("=== DIGITAL FORENSIC TOOL STARTED ===")
    print("Timestamp:", datetime.now())

    # FILE PATHS (CHANGE IF NEEDED)
    pcap_file = "network_data.csv"     # simplified PCAP summary
    log_file = "auth_logs.csv"

    # =========================
    # HASHING (BEFORE ANALYSIS) - ingress
    # =========================
    print("\n[+] Generating initial hashes...")
    pcap_hash_before = hash_evidence(pcap_file)
    log_hash_before = hash_evidence(log_file)

    print("PCAP Hash (Before):", pcap_hash_before)
    print("Log Hash  (Before):", log_hash_before)

    # =========================
    # NETWORK ANALYSIS
    # =========================
    print("\n[+] Performing network traffic analysis...")
    suspicious_ips, ip_counts = parse_pcap(pcap_file)

    print("Suspicious IPs from network traffic:")
    for ip in suspicious_ips:
        print("-", ip)

    # =========================
    # LOG ANALYSIS
    # =========================
    print("\n[+] Performing system log analysis...")
    failed_login_ips = analyze_logs(log_file)

    print("Failed login attempts by IP:")
    print(failed_login_ips)

    # =========================
    # HASHING (AFTER ANALYSIS) - egress
    # =========================
    print("\n[+] Verifying evidence integrity...")
    pcap_hash_after = hash_evidence(pcap_file)
    log_hash_after = hash_evidence(log_file)

    print("PCAP Hash (After):", pcap_hash_after)
    print("Log Hash  (After):", log_hash_after)

    # =========================
    # INTEGRITY CHECK (check evidence differences)
    # =========================
    if pcap_hash_before == pcap_hash_after and log_hash_before == log_hash_after:
        print("\n[✓] Evidence integrity verified. No modification detected.")
    else:
        print("\n[!] Evidence integrity compromised!")

    print("\n=== FORENSIC ANALYSIS COMPLETED ===")


# =========================
# PROGRAM ENTRY POINT
# =========================
if __name__ == "__main__":
    main()
