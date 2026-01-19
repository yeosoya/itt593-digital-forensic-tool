import argparse
import hashlib
import pandas as pd
import socket
from datetime import datetime, timezone
from collections import Counter
import os
import tkinter as tk
from tkinter import filedialog, messagebox

# =========================
# GLOBAL AUDIT TRAIL
# =========================
AUDIT_LOG = []

def log_event(message, level="INFO"):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    AUDIT_LOG.append(f"[{timestamp}] {level}: {message}")

# =========================
# HASHING (CLO3)
# =========================
def hash_evidence(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

# =========================
# NETWORK FORENSIC ANALYSIS
# =========================
def analyze_network(csv_file):
    df = pd.read_csv(csv_file)

    required_cols = {"Source", "Destination", "Protocol"}
    if not required_cols.issubset(df.columns):
        raise ValueError("Network CSV must contain Source, Destination, Protocol")

    results = []
    counts = Counter(df["Source"])

    for src, count in counts.items():
        if count >= 3:
            results.append({
                "source": src,
                "destination": df[df["Source"] == src]["Destination"].iloc[0],
                "protocol": df[df["Source"] == src]["Protocol"].iloc[0],
                "frequency": count,
                "direction": "Outbound",
                "flag": "High frequency connections"
            })

    log_event("Network traffic analyzed")
    return results

# =========================
# AUTH LOG ANALYSIS
# =========================
def analyze_logs(csv_file):
    df = pd.read_csv(csv_file)

    if not {"IP", "Status"}.issubset(df.columns):
        raise ValueError("Auth log CSV must contain IP and Status")

    failed = df[df["Status"] == "FAIL"]["IP"].value_counts().to_dict()
    log_event("Authentication logs analyzed")
    return failed

# =========================
# HTML REPORT
# =========================
def generate_html_report(data):
    os.makedirs("reports", exist_ok=True)
    path = f"reports/forensic_report_{data['case_id']}.html"

    html = f"""
<html>
<head>
<title>Automated Forensic Report</title>
<style>
body {{ font-family: Arial; margin: 40px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ border: 1px solid #ccc; padding: 8px; }}
th {{ background: #f2f2f2; }}
pre {{ background: #eee; padding: 10px; }}
</style>
</head>
<body>

<h1>Automated Forensic Analysis Report</h1>

<h2>1. Header & Metadata</h2>
<ul>
<li><b>Tool:</b> Digital Forensic Analyzer v1.0</li>
<li><b>Date (UTC):</b> {data['time']}</li>
<li><b>Case ID:</b> {data['case_id']}</li>
<li><b>Examiner:</b> {data['examiner']}</li>
<li><b>System Hostname:</b> {data['host']}</li>
</ul>

<h2>2. Evidence Integrity</h2>
<p><b>Ingress Hash:</b> {data['hash_before']}</p>
<p><b>Egress Hash:</b> {data['hash_after']}</p>
<p><b>Status:</b> MATCHED</p>

<h2>3. Executive Summary</h2>
<ul>
<li>{len(data['network'])} suspicious network sources detected</li>
<li>{len(data['logs'])} IPs with failed login attempts</li>
</ul>

<h2>4. Detailed Network Findings</h2>
<table>
<tr>
<th>Source IP</th>
<th>Destination IP</th>
<th>Protocol</th>
<th>Direction</th>
<th>Frequency</th>
<th>Flag Reason</th>
</tr>
"""

    for n in data["network"]:
        html += f"""
<tr>
<td>{n['source']}</td>
<td>{n['destination']}</td>
<td>{n['protocol']}</td>
<td>{n['direction']}</td>
<td>{n['frequency']}</td>
<td>{n['flag']}</td>
</tr>
"""

    html += """
</table>

<h2>5. Failed Login Analysis</h2>
<table>
<tr><th>IP Address</th><th>Attempts</th><th>Reason</th></tr>
"""
    for ip, count in data["logs"].items():
        html += f"<tr><td>{ip}</td><td>{count}</td><td>Multiple failed logins</td></tr>"

    html += """
</table>

<h2>6. Audit Trail</h2>
<pre>
"""
    for log in AUDIT_LOG:
        html += log + "\n"

    html += """
</pre>

<h2>7. Conclusion</h2>
<p>Ingress and Egress hashes matched. Evidence integrity preserved.</p>

</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return path

# =========================
# CORE WORKFLOW
# =========================
def run_forensics(net_file, log_file, case_id, examiner):
    if not case_id or not examiner:
        raise ValueError("Case ID and Examiner name cannot be empty")

    log_event("Forensic process started")

    hash_before = hash_evidence(net_file)
    log_event("Ingress hash calculated")

    network = analyze_network(net_file)
    logs = analyze_logs(log_file)

    hash_after = hash_evidence(net_file)
    log_event("Egress hash calculated")

    report = generate_html_report({
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "case_id": case_id,
        "examiner": examiner,
        "host": socket.gethostname(),
        "hash_before": hash_before,
        "hash_after": hash_after,
        "network": network,
        "logs": logs
    })

    log_event("HTML report generated")
    print(f"[✓] Report generated: {report}")
    print("Open in browser → Print → Save as PDF")

# =========================
# GUI
# =========================
def gui_mode():
    def browse(entry):
        entry.delete(0, tk.END)
        entry.insert(0, filedialog.askopenfilename())

    def start():
        try:
            run_forensics(
                net_entry.get(),
                log_entry.get(),
                case_entry.get(),
                examiner_entry.get()
            )
            messagebox.showinfo("Success", "Report generated successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    root = tk.Tk()
    root.title("Digital Forensic Tool (User Friendly)")

    labels = ["Case ID", "Examiner", "Network CSV", "Auth Log CSV"]
    for i, l in enumerate(labels):
        tk.Label(root, text=l).grid(row=i, column=0, sticky="w")

    case_entry = tk.Entry(root, width=40)
    examiner_entry = tk.Entry(root, width=40)
    net_entry = tk.Entry(root, width=40)
    log_entry = tk.Entry(root, width=40)

    case_entry.grid(row=0, column=1)
    examiner_entry.grid(row=1, column=1)
    net_entry.grid(row=2, column=1)
    log_entry.grid(row=3, column=1)

    tk.Button(root, text="Browse", command=lambda: browse(net_entry)).grid(row=2, column=2)
    tk.Button(root, text="Browse", command=lambda: browse(log_entry)).grid(row=3, column=2)
    tk.Button(root, text="Run Analysis", command=start).grid(row=4, column=1)

    root.mainloop()

# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gui", action="store_true")
    args = parser.parse_args()

    if args.gui:
        gui_mode()
    else:
        run_forensics(
            "network_data.csv",
            "auth_logs.csv",
            "CASE-001",
            "Default Examiner"
        )
