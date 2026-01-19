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
        "Forensic analysis completed.\nCheck terminal output."
    )

app = tk.Tk()
app.title("Digital Forensic Analysis Tool (ITT593)")

pcap_path = tk.StringVar()
log_path = tk.StringVar()

tk.Label(app, text="Network Evidence (CSV)").pack()
tk.Entry(app, textvariable=pcap_path, width=40).pack()
tk.Button(app, text="Browse", command=browse_pcap).pack()

tk.Label(app, text="Log Evidence (CSV)").pack()
tk.Entry(app, textvariable=log_path, width=40).pack()
tk.Button(app, text="Browse", command=browse_logs).pack()

tk.Button(app, text="Run Forensic Analysis", command=run_tool).pack(pady=10)

app.mainloop()
