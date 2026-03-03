# Enterprise Threat Hunting & Detection Engineering Using Splunk SIEM

## 📖 Executive Summary

This project demonstrates the design and implementation of an enterprise-style threat hunting and detection engineering lab using Splunk SIEM. The objective was to proactively identify adversary behaviors by leveraging centralized log analysis, custom detection rules, and hypothesis-driven hunting techniques mapped to the MITRE ATT&CK framework.

The lab simulates real-world attack scenarios including brute force attempts, PowerShell abuse, privilege escalation, and lateral movement in a controlled environment.

---

## 🏗 Lab Architecture

**Environment Setup:**
- macOS Host System
- Windows 10 Virtual Machine (Log Source)
- Kali Linux Virtual Machine (Attack Simulation)
- Splunk Enterprise SIEM
- Sysmon for enhanced Windows telemetry

**Log Sources Ingested:**
- Windows Security Event Logs
- Sysmon Operational Logs
- PowerShell Logs
- Authentication Logs

Logs were forwarded to Splunk for centralized monitoring and analysis.

---

## 🎯 Threat Hunting Objectives

The following adversarial techniques were modeled and detected:

| Technique | MITRE ATT&CK ID | Detection Strategy |
|------------|----------------|-------------------|
| Brute Force | T1110 | Threshold-based failed login detection |
| PowerShell Abuse | T1059.001 | Encoded command-line argument detection |
| Persistence via Registry | T1547 | Monitoring registry run key modifications |
| Lateral Movement | T1021 | Detection of abnormal remote authentication attempts |

---

## 🛠 Tools & Technologies

- Splunk Enterprise SIEM
- Sysmon (Windows System Monitoring)
- Windows Event Logging
- Kali Linux (Attack Simulation)
- MITRE ATT&CK Framework

---

## 🔍 Detection Engineering

Custom SPL queries were developed to detect suspicious activity, including:

- Excessive failed login attempts within defined time windows
- Suspicious PowerShell executions with encoded payloads
- Creation of new local administrative accounts
- Abnormal parent-child process relationships
- Network connections to rare external IP addresses

Each detection rule was validated through controlled attack simulations and tuned to minimize false positives.

---

## 🧠 Threat Hunting Methodology

A hypothesis-driven hunting approach was used:

1. Define adversary behavior hypothesis.
2. Map behavior to MITRE ATT&CK techniques.
3. Query relevant log sources.
4. Analyze anomalies and patterns.
5. Tune detection logic based on findings.

This proactive hunting approach enhances detection coverage beyond reactive alert monitoring.

---

## 📊 Dashboards & Monitoring

Custom Splunk dashboards were created to visualize:

- Authentication failure trends
- Suspicious process executions
- Administrative account activity
- Source IP distribution
- Timeline of simulated attack activity

---

## 🧪 Attack Simulation & Validation

Controlled simulations were conducted from Kali Linux to validate detection logic, including:

- Brute force login attempts
- Remote authentication attempts
- PowerShell command execution
- Registry modification tests

All detections were verified against generated logs to ensure accuracy and reliability.

---

## 📈 Key Outcomes

- Engineered 6+ custom detection rules
- Successfully mapped detections to MITRE ATT&CK techniques
- Reduced false positives through threshold tuning
- Developed analyst-level threat hunting queries
- Built real-time security monitoring dashboards

---

## 🔐 Conclusion

This project demonstrates practical experience in detection engineering, SIEM configuration, threat hunting, and incident analysis within a simulated enterprise environment. The implementation reflects a proactive and analytical approach aligned with Cyber Security Analyst responsibilities.
