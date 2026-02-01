import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
from collections import defaultdict

# ================= CONFIG =================
SUSPICIOUS_PORTS = [21, 22, 23, 25, 3389, 4444]
PORT_SCAN_THRESHOLD = 5

packet_count = 0
alerts = 0
sniffing = False

ip_port_counter = defaultdict(set)

# ================= GUI =================
root = tk.Tk()
root.title("Network Intrusion Detection System (Python)")
root.geometry("1050x650")
root.configure(bg="#020617")

COLORS = {
    "bg": "#020617",
    "title": "#22c55e",
    "info": "#38bdf8",
    "alert": "#ef4444",
    "warning": "#f97316",
    "success": "#10b981",
    "purple": "#a855f7",
    "yellow": "#facc15",
    "pink": "#ec4899",
    "gray": "#94a3b8"
}

# ================= TITLE =================
tk.Label(
    root,
    text="NETWORK INTRUSION DETECTION SYSTEM (IDS)",
    fg=COLORS["title"],
    bg=COLORS["bg"],
    font=("Consolas", 20, "bold")
).pack(pady=10)

stats = tk.Label(
    root,
    text="Packets: 0 | Alerts: 0",
    fg=COLORS["yellow"],
    bg=COLORS["bg"],
    font=("Consolas", 12, "bold")
)
stats.pack()

log_box = scrolledtext.ScrolledText(
    root,
    width=130,
    height=28,
    bg="#020617",
    fg=COLORS["gray"],
    insertbackground="white",
    font=("Consolas", 10)
)
log_box.pack(padx=10, pady=10)

log_box.tag_config("INFO", foreground=COLORS["info"])
log_box.tag_config("ALERT", foreground=COLORS["alert"], font=("Consolas", 10, "bold"))
log_box.tag_config("WARN", foreground=COLORS["warning"])
log_box.tag_config("OK", foreground=COLORS["success"])

# ================= IDS LOGIC =================
def log(level, msg):
    log_box.insert(tk.END, f"[{datetime.now()}] {msg}\n", level)
    log_box.see(tk.END)

def detect_intrusion(packet):
    global packet_count, alerts
    packet_count += 1

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

        # Port scan detection
        if TCP in packet:
            dport = packet[TCP].dport
            ip_port_counter[src].add(dport)

            if len(ip_port_counter[src]) > PORT_SCAN_THRESHOLD:
                alerts += 1
                log("ALERT", f"Port Scan Detected from {src}")
                ip_port_counter[src].clear()

            if dport in SUSPICIOUS_PORTS:
                alerts += 1
                log("ALERT", f"Suspicious Port Access {src} → {dport}")

        # ICMP flood (basic)
        if ICMP in packet:
            alerts += 1
            log("WARN", f"ICMP Traffic Detected from {src}")

    stats.config(text=f"Packets: {packet_count} | Alerts: {alerts}")

# ================= THREAD =================
def sniff_thread():
    sniff(prn=detect_intrusion, store=False)

def start_ids():
    global sniffing
    sniffing = True
    log("INFO", "IDS Monitoring Started")
    t = threading.Thread(target=sniff_thread, daemon=True)
    t.start()

def stop_ids():
    global sniffing
    sniffing = False
    log("OK", "IDS Monitoring Stopped")

# ================= BUTTONS =================
btn_frame = tk.Frame(root, bg=COLORS["bg"])
btn_frame.pack(pady=10)

tk.Button(
    btn_frame,
    text="START IDS",
    bg=COLORS["success"],
    fg="black",
    font=("Consolas", 12, "bold"),
    command=start_ids
).pack(side=tk.LEFT, padx=10)

tk.Button(
    btn_frame,
    text="STOP IDS",
    bg=COLORS["warning"],
    fg="black",
    font=("Consolas", 12, "bold"),
    command=stop_ids
).pack(side=tk.LEFT, padx=10)

# ================= FOOTER =================
tk.Label(
    root,
    text="Follow On Instagram :- codewithiitian",
    fg=COLORS["pink"],
    bg=COLORS["bg"],
    font=("Consolas", 12, "bold")
).pack(pady=5)

root.mainloop()
