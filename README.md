# Network Intrusion Detection System (Python)

A **Network-based Intrusion Detection System (IDS)** built using **Python, Scapy, and Tkinter** to monitor live network traffic, detect suspicious activities, and generate real-time alerts using rule-based detection logic.

This project is designed for educational purposes to demonstrate how IDS tools like Snort or Suricata work at a conceptual level.

---

## 🎯 Objectives

- Monitor network traffic continuously
- Detect suspicious or malicious behavior
- Generate alerts based on predefined rules
- Simulate intrusion response mechanisms
- Visualize alerts and statistics in a GUI dashboard

---

## 🚀 Features

- Live packet sniffing
- Rule-based intrusion detection
- Port scan detection
- Suspicious port access alerts
- ICMP traffic monitoring
- Real-time packet & alert counters
- Color-coded alert dashboard
- Start/Stop IDS controls
- Clean and user-friendly GUI

---

## 🔍 Detection Rules Implemented

- Port scanning detection (multiple ports from same IP)
- Access to commonly abused ports (FTP, SSH, Telnet, RDP, etc.)
- ICMP traffic alerts (basic flood indicator)

---

## 🛠️ Technologies Used

- Python 3
- Scapy (packet sniffing)
- Tkinter (GUI)
- Threading

---

## ▶️ How to Run

```bash
python ids.py
📊 Output

Real-time packet count

Alert count

Timestamped intrusion alerts

Visual IDS dashboard

⚠️ Disclaimer

This IDS is created strictly for learning and demonstration purposes.
It is not a replacement for production-grade IDS tools like Snort or Suricata.
