import argparse
import hashlib
import pandas as pd
import socket
from datetime import datetime, timezone, timedelta
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
# NF-UNSW-NB15 ANALYSIS
# (Single CSV with simulated forensic fields)
# =========================
def analyze_nf_unsw(csv_file):
    df = pd.read_csv(csv_file)

    required = {
        "L4_SRC_PORT",
        "L4_DST_PORT",
        "PROTOCOL",
        "FLOW_DURATION_MILLISECONDS",
        "Attack"
    }
    if not required.issubset(df.columns):
        raise ValueError("CSV does not match NF-UNSW-NB15 format")

    # -------------------------
    # SIMULATED TIMESTAMP
    # -------------------------
    base_time = datetime(2026, 1, 20, tzinfo=timezone.utc)
    df["Timestamp"] = [
        base_time + timedelta(milliseconds=int(x))
        for x in df["FLOW_DURATION_MILLISECONDS"].cumsum()
    ]

    # -------------------------
    # SIMULATED IP ADDRESSES
    # -------------------------
    df["Source"] = df["L4_SRC_PORT"].apply(
        lambda x: f"192.168.1.{int(x) % 254 + 1}"
    )
    df["Destination"] = df["L4_DST_PORT"].apply(
        lambda x: f"10.0.0.{int(x) % 254 + 1}"
    )
    df["Protocol"] = df["PROTOCOL"]

    # =========================
    # NETWORK FORENSIC FINDINGS
    # =========================
    network_results = []
    for src, group in df.groupby("Source"):
        if len(group) >= 3:
            network_results.append({
                "source": src,
                "destination": group["Destination"].iloc[0],
                "protocol": group["Protocol"].iloc[0],
                "frequency": len(group),
                "first_seen": group["Timestamp"].min(),
                "last_seen": group["Timestamp"].max(),
                "flag": "High frequency connections in short time window"
            })

    # =========================
    # AUTH / FAILED LOGIN (SIMULATED)
    # =========================
    failed = df[df["Attack"] != "Benign"]
    auth_results = []

    for ip, group in failed.groupby("Source"):
        auth_results.append({
            "ip": ip,
            "attempts": len(group),
            "first_attempt": group["Timestamp"].min(),
            "last_attempt": group["Timestamp"].max(),
            "duration": int(
                (group["Timestamp"].max() - group["Timestamp"].min())
                .total_seconds() / 60
            )
        })

    log_event("NF-UNSW-NB15 dataset analyzed with simulated timeline")
    return network_results, auth_results

# =========================
# HTML REPORT
# =========================
def generate_html_report(data):
    os.makedirs("reports", exist_ok=True)
    path = f"reports/forensic_report_{data['case_id']}.html"

    integrity = (
        "MATCHED"
        if data["hash_before"] == data["hash_after"]
        else "NOT MATCHED"
    )

    html = f"""
<!DOCTYPE html>
<html>
<head>
<title>PySecureTrace Forensic Report</title>
<style>
body {{
    font-family: Arial, Helvetica, sans-serif;
    margin: 30px;
    color: #000;
}}

h1 {{ text-align: center; }}

.section {{
    border: 1px solid #000;
    padding: 15px;
    margin-bottom: 20px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
    word-wrap: break-word;
}}

th, td {{
    border: 1px solid #000;
    padding: 6px;
    font-size: 12px;
    text-align: center;
    vertical-align: top;
}}

th {{
    background-color: #f2f2f2;
}}

pre {{
    font-size: 11px;
    white-space: pre-wrap;
}}

@media print {{
    table {{
        font-size: 10px;
    }}
}}
</style>
</head>

<body>

<h1>Automated Digital Forensic Analysis Report</h1>

<div class="section">
<h2>1. Header & Metadata</h2>
<ul>
<li><b>Date (UTC):</b> {data['time']}</li>
<li><b>Case ID:</b> {data['case_id']}</li>
<li><b>Examiner:</b> {data['examiner']}</li>
<li><b>System Hostname:</b> {data['host']}</li>
</ul>
</div>

<div class="section">
<h2>2. Evidence Integrity</h2>
<p><b>Ingress Hash (SHA-256):</b> {data['hash_before']}</p>
<p><b>Egress Hash (SHA-256):</b> {data['hash_after']}</p>
<p><b>Integrity Status:</b> {integrity}</p>
</div>

<div class="section">
<h2>3. Executive Summary</h2>
<ul>
<li>{len(data['network'])} suspicious network sources detected</li>
<li>{len(data['logs'])} IPs involved in failed authentication attempts</li>
</ul>
</div>

<div class="section">
<h2>4. Network Forensic Findings (Timeline-Based)</h2>
<table>
<tr>
<th>Source IP</th>
<th>Destination</th>
<th>Protocol</th>
<th>Frequency</th>
<th>First Seen</th>
<th>Last Seen</th>
<th>Flag</th>
</tr>
"""

    for n in data["network"]:
        html += f"""
<tr>
<td>{n['source']}</td>
<td>{n['destination']}</td>
<td>{n['protocol']}</td>
<td>{n['frequency']}</td>
<td>{n['first_seen']}</td>
<td>{n['last_seen']}</td>
<td>{n['flag']}</td>
</tr>
"""

    html += """
</table>
</div>

<div class="section">
<h2>5. Failed Login Analysis (Timeline)</h2>
<table>
<tr>
<th>IP Address</th>
<th>Attempts</th>
<th>First Attempt</th>
<th>Last Attempt</th>
<th>Duration (minutes)</th>
<th>Assessment</th>
</tr>
"""

    for l in data["logs"]:
        html += f"""
<tr>
<td>{l['ip']}</td>
<td>{l['attempts']}</td>
<td>{l['first_attempt']}</td>
<td>{l['last_attempt']}</td>
<td>{l['duration']}</td>
<td>Possible brute-force activity</td>
</tr>
"""

    html += """
</table>
</div>

<div class="section">
<h2>6. Audit Trail</h2>
<pre>
"""

    for log in AUDIT_LOG:
        html += log + "\n"

    html += """
</pre>
</div>

<div class="section">
<h2>7. Conclusion</h2>
<p>
Timeline correlation between abnormal network traffic and repeated authentication failures
indicates suspicious activity. Evidence integrity was preserved throughout the forensic process.
</p>
</div>

</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return path

# =========================
# CORE WORKFLOW
# =========================
def run_forensics(csv_file, case_id, examiner):
    log_event("Forensic process started")

    hash_before = hash_evidence(csv_file)
    network, logs = analyze_nf_unsw(csv_file)
    hash_after = hash_evidence(csv_file)

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

    print(f"[✓] Report generated: {report}")

# =========================
# GUI (BIGGER WINDOW)
# =========================
def gui_mode():
    def browse():
        entry.delete(0, tk.END)
        entry.insert(0, filedialog.askopenfilename())

    def start():
        try:
            run_forensics(entry.get(), case_entry.get(), examiner_entry.get())
            messagebox.showinfo("Success", "Report generated successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    root = tk.Tk()
    root.title("PySecureTrace – Digital Forensic Tool")
    root.geometry("600x300")
    root.resizable(True, True)

    tk.Label(root, text="Case ID").grid(row=0, column=0, padx=10, pady=10, sticky="w")
    tk.Label(root, text="Examiner").grid(row=1, column=0, padx=10, pady=10, sticky="w")
    tk.Label(root, text="NF-UNSW-NB15 CSV").grid(row=2, column=0, padx=10, pady=10, sticky="w")

    case_entry = tk.Entry(root, width=50)
    examiner_entry = tk.Entry(root, width=50)
    entry = tk.Entry(root, width=50)

    case_entry.grid(row=0, column=1, padx=10)
    examiner_entry.grid(row=1, column=1, padx=10)
    entry.grid(row=2, column=1, padx=10)

    tk.Button(root, text="Browse", command=browse).grid(row=2, column=2, padx=10)
    tk.Button(root, text="Run Analysis", command=start).grid(row=3, column=1, pady=20)

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
        run_forensics("NF-UNSW-NB15.csv", "CASE-001", "Default Examiner")
