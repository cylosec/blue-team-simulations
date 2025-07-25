# MITRE ATT&CK Mapping: SIM-002 – Lateral Movement and C2 Beaconing

## Overview

This document maps observed behaviors from the simulation to relevant MITRE ATT&CK tactics and techniques. The goal is to ensure accurate classification, improve detection coverage, and assist in creating threat-informed defense strategies.

---

## Tactic: Execution

| Technique Name                   | ID         | Description                                                    |
|----------------------------------|------------|----------------------------------------------------------------|
| PowerShell                       | T1059.001  | Use of `powershell.exe` to execute commands and scripts, often obfuscated or encoded to evade detection. |

**Evidence:**
- Encoded PowerShell command executed locally on WIN-DC01.
- Remote PowerShell execution on WIN-SQL01 via WMI.

---

## Tactic: Lateral Movement

| Technique Name                   | ID         | Description                                                    |
|----------------------------------|------------|----------------------------------------------------------------|
| Remote Services: WMI            | T1021.001  | Uses Windows Management Instrumentation for remote execution. Common in lateral movement scenarios. |

**Evidence:**
- `wmic.exe` used to remotely spawn a process on 192.168.1.12 (WIN-SQL01).
- Target system launched PowerShell process without user interaction.

---

## Tactic: Command and Control

| Technique Name                            | ID         | Description                                                    |
|-------------------------------------------|------------|----------------------------------------------------------------|
| Application Layer Protocol: Web Traffic   | T1071.001  | Uses HTTP(S) for C2 communication. Difficult to detect in environments with high web usage. |

**Evidence:**
- HTTP POST requests from WIN-SQL01 to external IP `185.199.111.29` over TCP port 8081.
- Beaconing behavior: consistent intervals and payload size.
- Suspicious DNS resolution of `c2-stage.cylosec-breach.com`.

---

## Additional Enrichment (Optional)

| ATT&CK Feature            | Value                                    |
|---------------------------|------------------------------------------|
| Software Used             | PowerShell, WMIC                        |
| Data Sources              | Sysmon logs, DNS logs, Network traffic  |
| Detection Recommendations | Monitor parent-child process chains, alert on abnormal use of WMIC, track unusual outbound traffic patterns |

---

## Notes

This simulation emphasizes the importance of correlating endpoint process behavior with network activity. It demonstrates how common administrative tools can be abused to bypass traditional detection mechanisms.

All mapped techniques are validated against the latest MITRE ATT&CK version: [https://attack.mitre.org](https://attack.mitre.org)

