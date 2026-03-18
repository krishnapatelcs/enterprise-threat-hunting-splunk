# Enterprise Threat Hunting & Detection Using Splunk SIEM

![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange) ![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red) ![Platform](https://img.shields.io/badge/Platform-macOS%20ARM64-blue) ![Status](https://img.shields.io/badge/Status-Completed-green)

## Executive Summary

This project demonstrates the design and implementation of an enterprise-style threat hunting and detection engineering lab using Splunk SIEM. Five custom detection rules were built, validated through controlled attack simulations, and mapped to the MITRE ATT&CK framework. The lab runs entirely on Apple Silicon Mac using UTM virtualization with Windows 11 ARM64 and Kali Linux VMs.

---

## Lab Architecture

| Component | Details |
|---|---|
| Host Machine | macOS (Apple Silicon M-series, UTM hypervisor) |
| Windows VM | Windows 11 ARM64 — log source & attack target (192.168.64.10) |
| Kali Linux VM | Attack platform (192.168.64.2) |
| SIEM | Splunk Enterprise Free Trial (172.16.37.32:8000) |
| Telemetry | Sysmon64a (ARM64 build) + Splunk Universal Forwarder |
| Framework | MITRE ATT&CK v14 |

---

## Detection Rules

| Rule | ATT&CK ID | Description | Key Event IDs |
|---|---|---|---|
| Brute Force Login Detection | T1110.001 | Detects 10+ failed logins from same IP in 5 minutes | 4625 |
| Login After Failures | T1110 | Detects successful login following 5+ failures | 4624, 4625 |
| Encoded PowerShell Execution | T1059.001 | Detects -EncodedCommand flag via Sysmon | Sysmon EID 1 |
| New Admin Account Creation | T1136.001 | Detects new user added to Administrators group | 4720, 4732 |
| Multi-Stage Attack Chain | T1110 + T1059.001 + T1136.001 | Correlates 3+ attack stages by Account_Name across brute force, execution, and persistence | 4625, 4624, Sysmon EID 1, 4720, 4732 |

---

## SPL Queries

**Rule 1 — Brute Force Detection**
```spl
index=wineventlog EventCode=4625
| bucket _time span=5m
| stats count by _time, Account_Name, Source_Network_Address
| where count > 10 | sort -count
```

**Rule 2 — Login After Failures**
```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
| eval status=if(EventCode=4624,"success","failure")
| stats count(eval(status="failure")) as fails,
        count(eval(status="success")) as successes
        by Account_Name, Source_Network_Address
| where fails>=5 AND successes>=1
```

**Rule 3 — Encoded PowerShell (Sysmon XML)**
```spl
index=sysmon source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search CommandLine="*EncodedCommand*" OR CommandLine="*-enc*"
| table _time, Image, CommandLine
```

**Rule 4 — New Admin Account**
```spl
index=wineventlog (EventCode=4720 OR EventCode=4732)
| table _time, EventCode, Account_Name, SubjectUserName
| sort -_time
```

**Rule 5 — Multi-Stage Attack Chain**
```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
| eval stage=case(
    EventCode=4625, "1_BruteForce",
    EventCode=4624, "2_InitialAccess")
| append [search index=sysmon source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
    | rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
    | search CommandLine="*EncodedCommand*" OR CommandLine="*-nop*"
    | eval stage="3_Execution", Source_Network_Address="sysmon"]
| append [search index=wineventlog (EventCode=4720 OR EventCode=4732)
    | eval stage="4_Persistence", Source_Network_Address="account_mgmt"]
| stats values(stage) as attack_stages, count by Account_Name
| where mvcount(attack_stages) >= 3
| eval chain=mvjoin(attack_stages, " → ")
| table Account_Name, chain, count
```

---

## Attack Simulations

All simulations were performed in an isolated lab environment.

- **Brute Force:** xfreerdp loop script — 20 failed RDP attempts from Kali Linux
- **Credential Compromise:** Successful RDP login after brute force — triggering Rule 2
- **Encoded PowerShell:** `powershell -EncodedCommand <base64>` executed on Windows VM
- **Admin Account Creation:** `net user hacker /add` + `net localgroup Administrators hacker /add`
- **Multi-Stage Chain:** Cumulative events from all simulations correlated automatically by Rule 5

---

## Validation Results

| Detection Rule | Alert Fired | False Positives | Key Findings |
|---|---|---|---|
| Rule 1 — Brute Force | ✅ Yes | None | 50 failed logins per 5-min bucket from 192.168.64.2 |
| Rule 2 — Login After Failure | ✅ Yes | None | 117 failures + 1 success from Kali IP |
| Rule 3 — Encoded PowerShell | ✅ Yes | None | 10 Sysmon EID 1 events with -EncodedCommand |
| Rule 4 — New Admin Account | ✅ Yes | None | EID 4720 + 4732 detected within seconds |
| Rule 5 — Multi-Stage Chain | ✅ Yes | None | Attack chain 1_BruteForce → 2_InitialAccess → 4_Persistence across 131 correlated events |

---

## Key Technical Findings

- **ARM64 Compatibility:** `Sysmon64.exe` fails on Apple Silicon VMs — `Sysmon64a.exe` is required
- **Field Names:** Windows Event Log uses `Source_Network_Address`, not `src_ip`
- **XML Parsing:** Sysmon uses `XmlWinEventLog` sourcetype — `rex` required to extract fields
- **Forwarder Permissions:** SplunkForwarder must run as Local System to read Sysmon channel

---

## Skills Demonstrated

- SIEM configuration and log pipeline management (Splunk + Universal Forwarder)
- Detection engineering with SPL (bucketing, eval, stats, rex, append, mvcount)
- Multi-stage attack chain correlation across multiple indexes and data sources
- Endpoint telemetry with Sysmon ARM64 deployment
- Hypothesis-driven threat hunting mapped to MITRE ATT&CK
- Attack simulation with xfreerdp and encoded PowerShell payloads
- SOC dashboard design for real-time visibility
- ARM64-specific troubleshooting in Apple Silicon home lab

---

*Built by Krishna Patel | Cybersecurity Analyst | March 2026*
