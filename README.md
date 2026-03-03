# Enterprise Threat Hunting & Detection Engineering Using Splunk SIEM

## 📌 Project Overview
This project demonstrates the implementation of a threat hunting and detection engineering lab using Splunk SIEM. The objective is to proactively detect adversary techniques mapped to the MITRE ATT&CK framework.

## 🏗 Lab Architecture
- Windows 10 VM (Log Source)
- Kali Linux VM (Attack Simulation)
- Splunk Enterprise (SIEM)
- Sysmon for enhanced Windows logging

## 🎯 Threat Hunting Objectives
- Detect brute force authentication attempts (T1110)
- Identify suspicious PowerShell activity (T1059.001)
- Monitor account creation and privilege escalation (T1547)
- Detect lateral movement attempts (T1021)

## 🛠 Tools Used
- Splunk Enterprise
- Sysmon
- Windows Event Logs
- Kali Linux
- MITRE ATT&CK Framework

## 🔎 Detection Engineering
Custom SPL detection queries were created to identify:
- Excessive failed logins
- Encoded PowerShell commands
- Suspicious process parent-child relationships
- New local admin account creation

## 📊 Dashboard & Monitoring
Security dashboards were built to visualize:
- Authentication trends
- Top source IP addresses
- Suspicious processes
- Administrative activity

## 📄 Documentation
A detailed threat hunting report including detection logic, validation testing, and tuning methodology is included in this repository.
