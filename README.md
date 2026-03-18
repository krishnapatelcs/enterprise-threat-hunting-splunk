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

## Tools & Resources

| Tool | Purpose | Link |
|---|---|---|
| Splunk Enterprise | SIEM platform for log ingestion, detection, and dashboards | [Download](https://www.splunk.com/en_us/download/splunk-enterprise.html) |
| Splunk Universal Forwarder | Ships logs from Windows VM to Splunk | [Download](https://www.splunk.com/en_us/download/universal-forwarder.html) |
| Sysmon (Sysinternals) | Enhanced Windows endpoint telemetry | [Download](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| SwiftOnSecurity Sysmon Config | Production-ready Sysmon configuration file | [GitHub](https://github.com/SwiftOnSecurity/sysmon-config) |
| UTM Hypervisor | ARM64 virtualization on Apple Silicon Mac | [Download](https://mac.getutm.app/) |
| Kali Linux | Attack simulation platform | [Download](https://www.kali.org/get-kali/) |
| Windows 11 ARM64 | Target endpoint and log source | [Download](https://www.microsoft.com/en-us/software-download/windows11) |
| MITRE ATT&CK Framework | Threat intelligence and technique mapping | [Website](https://attack.mitre.org/) |
| xfreerdp | RDP client for attack simulation from Kali | Pre-installed on Kali Linux |
| Hydra | Password brute-force tool (tested, replaced with loop script) | Pre-installed on Kali Linux |

---

## Detection Rules

| Rule | ATT&CK ID | Description | Key Event IDs |
|---|---|---|---|
| Brute Force Login Detection | T1110.001 | Detects 10+ failed logins from same IP in 5 minutes | 4625 |
| Login After Failures | T1110 | Detects successful login following 5+ failures | 4624, 4625 |
| Encoded PowerShell Execution | T1059.001 | Detects -EncodedCommand flag via Sysmon | Sysmon EID 1 |
| New Admin Account Creation | T1136.001 | Detects new user added to Administrators group | 4720, 4732 |
| Multi-Stage Attack Chain | T1110 + T1059.001 + T1136.001 | Correlates 3+ attack stages across brute force, execution, and persistence | 4625, 4624, Sysmon EID 1, 4720, 4732 |

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

## Full Project Command Reference

A complete step-by-step record of every command run during this project.

### Step 1 — Sysmon Installation (Windows 11 ARM64)

> **Note:** Standard `Sysmon64.exe` fails on ARM64 Windows with `errorCode=5`. Use `Sysmon64a.exe` — the ARM64-specific binary included in the same download package.

```cmd
:: Navigate to Sysmon directory
cd C:\Tools\Sysmon

:: Install Sysmon with SwiftOnSecurity config (ARM64 binary)
Sysmon64a.exe -accepteula -i sysmonconfig-export.xml

:: Verify Sysmon is running
sc query sysmon64a
```

Expected output:
```
SERVICE_NAME: sysmon64a
    STATE : 4  RUNNING
```

---

### Step 2 — Windows Audit Policy Configuration

```cmd
:: Apply Group Policy changes immediately
gpupdate /force

:: Verify each audit subcategory
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"Account Lockout"
auditpol /get /subcategory:"User Account Management"
auditpol /get /subcategory:"Process Creation"
```

Enable via `gpedit.msc`:
```
Computer Configuration → Windows Settings → Security Settings
→ Local Policies → Audit Policy
→ Enable: Audit logon events, Audit account management,
          Audit process tracking (Success & Failure)

Computer Configuration → Administrative Templates
→ Windows Components → Windows PowerShell
→ Turn on PowerShell Script Block Logging → Enabled
```

---

### Step 3 — Enable RDP on Windows VM

```cmd
:: Open RDP port in Windows Firewall
netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=in localport=3389 action=allow

:: Check Windows VM IP address
ipconfig
```

Enable via `sysdm.cpl` → Remote tab → Allow remote connections

---

### Step 4 — Splunk Setup (macOS)

```bash
# Start Splunk
cd /Applications/splunk/bin
./splunk start --accept-license

# Enable Splunk on boot
./splunk enable boot-start

# Access Splunk: http://127.0.0.1:8000
```

In Splunk web UI:
```
Settings → Forwarding and Receiving → Configure Receiving → Add New → Port: 9997
Settings → Indexes → New Index → Name: wineventlog
Settings → Indexes → New Index → Name: sysmon
```

---

### Step 5 — Splunk Universal Forwarder Setup (Windows VM)

```cmd
:: Navigate to local config folder
cd "C:\Program Files\SplunkUniversalForwarder\etc\apps\SplunkUniversalForwarder\local"

:: Create inputs.conf
notepad inputs.conf
```

Paste into inputs.conf:
```ini
[WinEventLog://Security]
disabled = false
index = wineventlog

[WinEventLog://System]
disabled = false
index = wineventlog

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
renderXml = true
index = sysmon
```

```cmd
:: Rename if Notepad added .txt extension
ren inputs.conf.txt inputs.conf

:: Fix Sysmon channel permissions
wevtutil set-log "Microsoft-Windows-Sysmon/Operational" /ca:"O:BAG:SYD:(A;;0x1;;;SY)(A;;0x1;;;BA)(A;;0x1;;;NS)"

:: Restart the forwarder
cd "C:\Program Files\SplunkUniversalForwarder\bin"
splunk restart

:: Verify forwarder is running
sc query SplunkForwarder

:: Verify outputs.conf points to Splunk host
type "C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf"
```

> **Note:** In `services.msc`, set SplunkForwarder to run as **Local System account** to resolve Sysmon channel permission errors.

---

### Step 6 — Verify Logs in Splunk

```spl
index=wineventlog | head 10
index=sysmon | head 10
index=wineventlog | stats count by EventCode | sort -count
```

Test connectivity from Windows VM:
```powershell
Test-NetConnection -ComputerName 172.16.37.32 -Port 9997
```

---

### Step 7 — Attack Simulations (Kali Linux)

**Single failed RDP login:**
```bash
xfreerdp /u:wronguser /p:wrongpass /v:192.168.64.10
```

**Brute force simulation — 20 failed attempts (triggers Rule 1):**
```bash
for i in {1..20}; do
  xfreerdp /u:administrator /p:wrongpass$i /v:192.168.64.10 +auth-only 2>/dev/null
  echo "Attempt $i done"
done
```

**Successful login after brute force (triggers Rule 2):**
```bash
xfreerdp /u:Krishna /p:windows /v:192.168.64.10
```

---

### Step 8 — Attack Simulations (Windows VM)

**Disable Windows Defender for simulation:**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**Generate and run encoded PowerShell (triggers Rule 3):**
```powershell
$command = "Write-Host 'Simulated Attack'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
Write-Host $encoded

powershell -EncodedCommand <paste_encoded_output_here>
```

**Create new admin account (triggers Rule 4):**
```cmd
net user hacker P@ssword123! /add
net localgroup Administrators hacker /add
```

**Rule 5 (Multi-Stage Chain) fires automatically** from the cumulative events of Steps 7 and 8.

---

## Attack Simulations Summary

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
- **Hydra RDP Module:** Experimental and unreliable on ARM64 — replaced with xfreerdp loop script
- **Account Lockout:** Disable lockout policy on Windows VM before running brute force simulations

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

## Project Report

Full project documentation including all screenshots, SPL queries, risk assessment, and lessons learned is available in the repository: [Final_Project_Definition.pdf](./Final_Project_Definition.pdf)

---

*Built by Krishna Patel | Cybersecurity Analyst | March 2026*
