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
| Splunk Enterprise | SIEM platform | [Download](https://www.splunk.com/en_us/download/splunk-enterprise.html) |
| Splunk Universal Forwarder | Ships logs from Windows VM to Splunk | [Download](https://www.splunk.com/en_us/download/universal-forwarder.html) |
| Sysmon (Sysinternals) | Enhanced Windows endpoint telemetry | [Download](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| SwiftOnSecurity Sysmon Config | Production-ready Sysmon configuration | [GitHub](https://github.com/SwiftOnSecurity/sysmon-config) |
| UTM Hypervisor | ARM64 virtualization on Apple Silicon | [Download](https://mac.getutm.app/) |
| Kali Linux | Attack simulation platform | [Download](https://www.kali.org/get-kali/) |
| Windows 11 ARM64 | Target endpoint and log source | [Download](https://www.microsoft.com/en-us/software-download/windows11) |
| MITRE ATT&CK | Threat intelligence and technique mapping | [Website](https://attack.mitre.org/) |
| xfreerdp | RDP client for Kali attack simulation | Pre-installed on Kali Linux |
| Hydra | Brute-force tool (tested, replaced with loop script) | Pre-installed on Kali Linux |

---

## Detection Rules

| Rule | ATT&CK ID | Description | Key Event IDs |
|---|---|---|---|
| Rule 1 — Brute Force Login Detection | T1110.001 | Detects 10+ failed logins from same IP in 5 minutes | 4625 |
| Rule 2 — Login After Failures | T1110 | Detects successful login following 5+ failures | 4624, 4625 |
| Rule 3 — Encoded PowerShell Execution | T1059.001 | Detects -EncodedCommand flag via Sysmon | Sysmon EID 1 |
| Rule 4 — New Admin Account Creation | T1136.001 | Detects new user added to Administrators group | 4720, 4732 |
| Rule 5 — Multi-Stage Attack Chain | T1110 + T1059.001 + T1136.001 | Correlates 3+ attack stages across brute force, execution, and persistence | 4625, 4624, Sysmon EID 1, 4720, 4732 |

---

## Project Walkthrough — Step by Step

A complete record of everything done in this project from start to finish.

---

### Step 1 — Install Sysmon on Windows 11 VM

**Downloads required:**
- [Sysmon (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) — download ZIP, extract `sysmonconfig-export.xml`

Place both files in `C:\Tools\Sysmon\`

> ⚠️ **ARM64 Note:** `Sysmon64.exe` fails on Apple Silicon VMs with `errorCode=5`. Use `Sysmon64a.exe` — the ARM64 binary included in the same download package.

Open **CMD as Administrator** and run:
```cmd
cd C:\Tools\Sysmon
Sysmon64a.exe -accepteula -i sysmonconfig-export.xml
```

Verify it is running:
```cmd
sc query sysmon64a
```

Expected output:
```
SERVICE_NAME: sysmon64a
    STATE : 4  RUNNING
```

Verify logs appear in Event Viewer:
```
Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

---

### Step 2 — Enable Windows Audit Policies

Open `gpedit.msc` and navigate to:
```
Computer Configuration → Windows Settings → Security Settings
→ Local Policies → Audit Policy
```

Enable **Success and Failure** for:
- Audit logon events
- Audit account management
- Audit process tracking

Also enable PowerShell Script Block Logging:
```
Computer Configuration → Administrative Templates
→ Windows Components → Windows PowerShell
→ Turn on PowerShell Script Block Logging → Enabled
```

Apply changes:
```cmd
gpupdate /force
```

Verify each policy:
```cmd
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"Account Lockout"
auditpol /get /subcategory:"User Account Management"
auditpol /get /subcategory:"Process Creation"
```

All four should show `Success and Failure`.

---

### Step 3 — Enable RDP on Windows VM

Open `sysdm.cpl` → **Remote** tab → select **Allow remote connections to this computer**

Open firewall port:
```cmd
netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=in localport=3389 action=allow
```

Find your Windows VM IP:
```cmd
ipconfig
```

Test from Kali to confirm RDP is reachable:
```bash
xfreerdp /u:wronguser /p:wrongpass /v:192.168.64.10
```

A login failure (not a connection failure) confirms RDP is working and generating Event ID 4625.

---

### Step 4 — Install Splunk Enterprise on Mac

Download from [splunk.com](https://www.splunk.com/en_us/download/splunk-enterprise.html) — select **macOS .dmg**

After installing, open **Terminal** on Mac:
```bash
cd /Applications/splunk/bin
./splunk start --accept-license
./splunk enable boot-start
```

Access Splunk in browser:
```
http://127.0.0.1:8000
```

---

### Step 5 — Configure Splunk to Receive Logs

In Splunk web UI:

**Enable receiving on port 9997:**
```
Settings → Forwarding and Receiving → Receive Data → Configure Receiving → Add New → 9997 → Save
```

**Create indexes:**
```
Settings → Indexes → New Index → Name: wineventlog → Save
Settings → Indexes → New Index → Name: sysmon → Save
```

---

### Step 6 — Install Splunk Universal Forwarder on Windows VM

Download from [splunk.com](https://www.splunk.com/en_us/download/universal-forwarder.html) — select **Windows 64-bit MSI**

During installation:
- Select **An on-premises Splunk Enterprise instance**
- **Deployment Server:** leave blank
- **Receiving Indexer:** enter your Mac IP and port `172.16.37.32:9997`

After installation, navigate to the local config folder:
```cmd
cd "C:\Program Files\SplunkUniversalForwarder\etc\apps\SplunkUniversalForwarder\local"
notepad inputs.conf
```

Paste this content:
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

Save the file. If Notepad added `.txt`:
```cmd
ren inputs.conf.txt inputs.conf
```

Fix Sysmon channel permissions:
```cmd
wevtutil set-log "Microsoft-Windows-Sysmon/Operational" /ca:"O:BAG:SYD:(A;;0x1;;;SY)(A;;0x1;;;BA)(A;;0x1;;;NS)"
```

> ⚠️ Open `services.msc` → find **SplunkForwarder** → Properties → Log On tab → select **Local System account** → OK

Restart the forwarder:
```cmd
cd "C:\Program Files\SplunkUniversalForwarder\bin"
splunk restart
```

Verify it is running:
```cmd
sc query SplunkForwarder
```

Verify connectivity from Windows VM:
```powershell
Test-NetConnection -ComputerName 172.16.37.32 -Port 9997
```

Should show `TcpTestSucceeded : True`

---

### Step 7 — Verify Logs Are Flowing in Splunk

In Splunk Search & Reporting, run with **All time** selected:
```
index=wineventlog | head 10
index=sysmon | head 10
```

Both should return events. If sysmon returns nothing, check:
```cmd
type "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log" | findstr ERROR
```

---

### Step 8 — Build Detection Rules in Splunk

For each rule, run the SPL search in Splunk → click **Save As → Alert** → set:
- Alert type: **Real-time**
- Trigger condition: **Per-Result**
- Trigger action: **Add to Triggered Alerts**

**Rule 1 — Brute Force Login Detection (T1110.001)**
```spl
index=wineventlog EventCode=4625
| bucket _time span=5m
| stats count by _time, Account_Name, Source_Network_Address
| where count > 10 | sort -count
```

**Rule 2 — Login After Failures (T1110)**
```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
| eval status=if(EventCode=4624,"success","failure")
| stats count(eval(status="failure")) as fails,
        count(eval(status="success")) as successes
        by Account_Name, Source_Network_Address
| where fails>=5 AND successes>=1
```

**Rule 3 — Encoded PowerShell (T1059.001)**
```spl
index=sysmon source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search CommandLine="*EncodedCommand*" OR CommandLine="*-enc*"
| table _time, Image, CommandLine
```

**Rule 4 — New Admin Account Creation (T1136.001)**
```spl
index=wineventlog (EventCode=4720 OR EventCode=4732)
| table _time, EventCode, Account_Name, SubjectUserName
| sort -_time
```

**Rule 5 — Multi-Stage Attack Chain (T1110 + T1059.001 + T1136.001)**
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

### Step 9 — Run Attack Simulations

> ⚠️ All simulations performed in an isolated lab environment. No real systems or networks were targeted.

**On Kali Linux — Single failed RDP login (confirms Event ID 4625 capture):**
```bash
xfreerdp /u:wronguser /p:wrongpass /v:192.168.64.10
```

**On Kali Linux — Brute force simulation (triggers Rule 1):**
```bash
for i in {1..20}; do
  xfreerdp /u:administrator /p:wrongpass$i /v:192.168.64.10 +auth-only 2>/dev/null
  echo "Attempt $i done"
done
```

**On Kali Linux — Successful login after failures (triggers Rule 2):**
```bash
xfreerdp /u:Krishna /p:windows /v:192.168.64.10
```

**On Windows VM — Disable Defender temporarily:**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**On Windows VM — Encoded PowerShell simulation (triggers Rule 3):**
```powershell
$command = "Write-Host 'Simulated Attack'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
Write-Host $encoded

powershell -EncodedCommand <paste_encoded_output_here>
```

**On Windows VM — New admin account creation (triggers Rule 4):**
```cmd
net user hacker P@ssword123! /add
net localgroup Administrators hacker /add
```

**Rule 5 fires automatically** from the cumulative events of all simulations above.

---

### Step 10 — Build SOC Dashboard in Splunk

In Splunk: **Dashboards → Create New Dashboard**

- Title: `Enterprise Threat Hunting SOC Dashboard`
- Type: Classic Dashboard

Add the following panels:

**Panel 1 — Failed Login Attempts Over Time**
```spl
index=wineventlog EventCode=4625
| timechart span=5m count as "Failed Logins"
```
Type: Line Chart

**Panel 2 — Top Source IPs with Failed Logins**
```spl
index=wineventlog EventCode=4625
| stats count by Source_Network_Address
| sort -count | head 10
```
Type: Bar Chart

**Panel 3 — Suspicious PowerShell Executions**
```spl
index=sysmon source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search CommandLine="*EncodedCommand*" OR CommandLine="*-enc*"
| table _time, Image, CommandLine
```
Type: Statistics Table

**Panel 4 — New Admin Account Creation Events**
```spl
index=wineventlog (EventCode=4720 OR EventCode=4732)
| table _time, EventCode, Account_Name, SubjectUserName
| sort -_time
```
Type: Statistics Table

**Panel 5 — Multi-Stage Attack Chain**
```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
| eval stage=case(EventCode=4625,"1_BruteForce",EventCode=4624,"2_InitialAccess")
| append [search index=wineventlog (EventCode=4720 OR EventCode=4732)
    | eval stage="4_Persistence"]
| stats values(stage) as attack_stages by Account_Name
| where mvcount(attack_stages) >= 2
| eval chain=mvjoin(attack_stages," → ")
| table Account_Name, chain
```
Type: Statistics Table

Click **Save**.

---

## Validation Results

| Detection Rule | Alert Fired | False Positives | Key Findings |
|---|---|---|---|
| Rule 1 — Brute Force | ✅ Yes | None | 50 failed logins per 5-min bucket from 192.168.64.2 |
| Rule 2 — Login After Failure | ✅ Yes | None | 117 failures + 1 success from Kali IP |
| Rule 3 — Encoded PowerShell | ✅ Yes | None | 10 Sysmon EID 1 events with -EncodedCommand |
| Rule 4 — New Admin Account | ✅ Yes | None | EID 4720 + 4732 detected within seconds |
| Rule 5 — Multi-Stage Chain | ✅ Yes | None | Attack chain 1_BruteForce → 2_InitialAccess → 4_Persistence across 131 events |

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

Full project documentation including all screenshots, SPL queries, risk assessment, and lessons learned: [Final_Project_Definition.pdf](./Final_Project_Definition.pdf)

---

*Built by Krishna Patel | Cybersecurity Analyst | March 2026*
