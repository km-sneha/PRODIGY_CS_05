# Task 5: Network Packet Analyzer

## Overview

This project implements a **network packet analyzer** that captures and displays network packets. It provides essential information such as **source and destination IP addresses**, **protocol types**, and **payload data**. Ethical use of this tool is paramount, and it should only be used in controlled or authorized environments.

---

## 🔍 Features

* Captures network packets and displays:

  * Source and destination IP addresses
  * Protocol types (TCP, UDP, ICMP, OTHER)
  * Payload data (if available)
* Saves captured data to a **timestamped log file**
* Supports **interface selection** for packet capture
* Real-time display of captured packet details

---

## 🛠️ How It Works

* **Packet Capture**:

  * Uses `scapy` to capture network packets on the selected interface.
* **Protocol Identification**:

  * Identifies protocols such as **TCP**, **UDP**, **ICMP**, and others.
* **Payload Handling**:

  * Attempts to decode payload data as UTF-8, while gracefully handling decoding errors.
* **Data Logging**:

  * Logs packet details and payload (if decoded) to a text file.

> 💡 Note: Run this script as an **Administrator** to capture network packets.

---

## 📦 Requirements

* Python 3.x
* Libraries:

  * `scapy`
  * `colorama`

To install the required libraries:

```
pip install scapy colorama
```

---

## 🚀 How to Run

1. Run the Python script using the command:

```
python packet_analyzer.py
```

2. Select the network interface from the displayed list.
3. The tool will start capturing packets in real time.
4. Press **Ctrl + C** to stop the capture.

---

## 💡 Suggestions for Improvement

* Add support for filtering by specific protocols.
* Implement GUI for easier interface selection.

---

## 👨‍💻 Developed By

**SNEHA K M**
*ProDigy Infotech Internship Project*

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes only**. Unauthorized use of packet sniffers is illegal and unethical. Always obtain proper consent before using this tool.
