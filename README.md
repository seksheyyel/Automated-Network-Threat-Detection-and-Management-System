# Automated Network Threat Detection and Management System

## About the Project

The Automated Network Threat Detection and Management System is developed using **Python, Flask, Scapy, and MySQL**. It automatically monitors network traffic on the computer where it is installed and detects common network threats such as:

- ARP Spoofing
- DDoS Attacks
- Port Scanning

When a threat is detected, the system automatically records the event in the database and displays an alert through a web-based dashboard. It provides administrators with real-time monitoring, threat detection, and security event management to help protect the monitored device from potential network attacks.

---

## Purpose

The purpose of this project is to provide an automated network security solution that monitors network traffic in real time, detects common network threats, records security events, and assists administrators in managing and responding to detected threats through a web-based dashboard.

---

## Features

- User Login Authentication
- Real-Time Packet Monitoring
- ARP Spoofing Detection
- DDoS Detection
- Port Scan Detection
- Alert Logging
- IP Whitelist Management
- Audit Logs
- Flask Web Dashboard
- MySQL Database

---

## Technologies Used

- Python
- Flask
- Scapy
- MySQL
- HTML
- CSS
- JavaScript
- Bootstrap

---

## How to Run

1. Install Python 3.
2. Install the required packages.

```bash
pip install -r requirements.txt
```

3. Import the provided SQL database.
4. Configure the database connection in `app.py`.
5. Run the application.

```bash
python app.py
```

6. Open your browser and go to:

```
http://localhost:5000
```

---

## Developers

- Ryan Macapayag
- Derek Angelo Manzo
- John Reuben Bautista
- Jhon Paulo Genandoy
- Angelo Calubihan
