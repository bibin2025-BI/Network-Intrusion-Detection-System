# Network-Intrusion-Detection-System
A Network Intrusion Detection System (NIDS) is a security solution that monitors network traffic for suspicious activity, policy violations, or known cyber threats. By analyzing packet payloads and data headers in real-time.
# Network Intrusion Detection System (NIDS)

A lightweight, real-time Network Intrusion Detection System (NIDS) written in Python for Windows environments. This tool monitors network traffic across your active network adapters, analyzes packet behavior, and flags potential malicious activity—such as port scanning, SYN flooding, and signature-based threats—using a combination of packet heuristics and signature matching.

---

## 🚀 Features

*   **Real-Time Packet Sniffing:** Efficient Windows packet capture utilizing `scapy` layered over Npcap.
*   **Protocol Analysis:** Deep inspection of Layer 2, 3, and 4 protocols (Ethernet, IPv4, IPv6, TCP, UDP, ICMP).
*   **Anomalous Heuristics:**
    *   **SYN Flood Detection:** Flags IPs sending disproportionate connection requests without completing the handshake.
    *   **Port Scan Detection:** Tracks unique port connection attempts per source IP over time.
    *   **Payload Inspection:** Matches signatures against known malicious strings or regex patterns.
*   **Alerting & Logging:** Structured JSON logs and real-time console alerts.

---

## 🛠️ Prerequisites

Because this script puts your network adapter into **promiscuous mode** to sniff traffic, it requires administrator privileges and a Windows packet capture driver.

1. **Python 3.8+**: Ensure Python is added to your system `PATH` during installation.
2. **Npcap**: Download and install [Npcap](https://npcap.com/). 
   * *Note: During installation, make sure to check the box that says **"Install Npcap in WinPcap API-compatible Mode"** if your Scapy version requires legacy bindings.*

---

## 📦 Installation

Open **PowerShell** or **Command Prompt** as an **Administrator** and run the following:

1. **Clone the repository:**
   ```cmd
   git clone [https://github.com/bibin2025-BI/Network-Intrusion-Detection-System.git](https://github.com/bibin2025-BI/Network-Intrusion-Detection-System.git)
   cd Network-Intrusion-Detection-System

   python -m venv venv
.\venv\Scripts\activate

pip install -r requirements.txt

config.json
{
  "interface": "Wi-Fi",
  "rules": {
    "port_scan_threshold": 20,
    "port_scan_window_seconds": 10,
    "syn_flood_threshold": 50,
    "syn_flood_window_seconds": 5
  },
  "malicious_signatures": [
    "malware_cnc_string",
    "sql_injection_attempt_regex"
  ]
}

python main.py --list-interfaces

python main.py -i "Wi-Fi"

DOS
Options:
  -i, --interface TEXT  Name or GUID of the Windows network adapter.
  -c, --config TEXT     Path to custom config.json file.
  --list-interfaces     List all available network adapters and exit.
  --verbose             Enable verbose debug logging.
  --help                Show this message and exit.

  
