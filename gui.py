import tkinter as tk
from tkinter import filedialog, messagebox
from digital_forensic_tool import run_forensic_tool

def browse_pcap():
    pcap_path.set(filedialog.askopenfilename())

def browse_logs():
    log_path.set(filedialog.askopenfilename())

def run_tool():
    if not pcap_path.get() or not log_path.get():
        messagebox.showerror("Error", "Please select both files")
        return

    run_forensic_tool(
        pcap_file=pcap_path.get(),
        log_file=log_path.get()
    )

    messagebox.showinfo(
        "Completed",
        "Forensic analysis completed.\nCheck generated report."
    )

# =========================
# MAIN WINDOW
# =========================
app = tk.Tk()
app.title("Digital Forensic Analysis Tool (ITT593)")
app.geometry("500x320")

pcap_path = tk.StringVar()
log_path = tk.StringVar()

# =========================
# CENTERED TITLE
# =========================
title_label = tk.Label(
    app,
    text="Digital Forensic Analysis Tool (ITT593)",
    font=("Arial", 16, "bold")
)
title_label.pack(pady=15)

subtitle = tk.Label(
    app,
    text="Automated Network & Log Forensic Analysis",
    font=("Arial", 10)
)
subtitle.pack(pady=5)

# =========================
# INPUT SECTION
# =========================
frame = tk.Frame(app)
frame.pack(pady=15)

tk.Label(frame, text="Network Evidence (CSV)").grid(row=0, column=0, sticky="w")
tk.Entry(frame, textvariable=pcap_path, width=40).grid(row=0, column=1)
tk.Button(frame, text="Browse", command=browse_pcap).grid(row=0, column=2, padx=5)

tk.Label(frame, text="Log Evidence (CSV)").grid(row=1, column=0, sticky="w", pady=8)
tk.Entry(frame, textvariable=log_path, width=40).grid(row=1, column=1)
tk.Button(frame, text="Browse", command=browse_logs).grid(row=1, column=2, padx=5)

# =========================
# RUN BUTTON
# =========================
tk.Button(
    app,
    text="Run Forensic Analysis",
    font=("Arial", 11, "bold"),
    bg="#2c3e50",
    fg="white",
    padx=10,
    pady=5,
    command=run_tool
).pack(pady=20)

app.mainloop()
