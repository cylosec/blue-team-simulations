# True Positive Detection: WinRM Configuration Abuse for Lateral Movement

**MITRE ATT&CK Techniques:**  
- `T1059.003` – Command and Scripting Interpreter: Windows Command Shell  
- `T1021.006` – Remote Services: Windows Remote Management  
- `T1078` – Valid Accounts  
- `T1569.002` – System Services: Service Execution

---

## Summary

A suspicious process execution alert was triggered by Sysmon Event ID 1, where `cscript.exe` was used to run `winrm.vbs` with elevated privileges. Initial review suggested a benign configuration task; however, further investigation revealed follow-up indicators of **unauthorized remote access and lateral movement**.

---

## Affected Host

| Field | Value |
|-------|-------|
| Hostname | WIN-1T5RE39Q2K5 |
| IP Address | 10.0.0.9 |
| Domain User | CYLOSEC\Administrator |
| Integrity Level | High (Admin) |
| Time | 2025-07-10 03:30:55 UTC |

---

## Process Execution Details

| Field | Value |
|-------|-------|
| Executable | `cscript.exe` |
| CommandLine | `cscript //nologo "C:\Windows\System32\winrm.vbs" set winrm/config/client/auth @{Basic="true"}` |
| Parent | `cmd.exe` |
| Parent CommandLine | `"C:\Windows\System32\cmd.exe" /c winrm.cmd ...` |
| SHA256 | `D84F0894D9E651E1C1485BE00A12C6EF0513FF3CCBB68BA0008CC8BEECB78849` |

---

## Timeline & Escalation Evidence

| Time | Event | Description |
|------|-------|-------------|
| 03:30:55 | Sysmon Event ID 1 | Execution of `cscript winrm.vbs` |
| 03:30:58 | Sysmon Event ID 3 | Network connection to 10.0.0.25:5985 |
| 03:31:02 | Windows Event ID 4624 | Successful remote interactive logon |
| 03:31:05 | Sysmon Event ID 1 | Execution of encoded PowerShell on remote host |
| 03:31:10 | Windows Event ID 7045 | New service `winmgmtsvc` installed remotely |

---

## Analyst Determination

This behavior is consistent with adversary techniques used post-compromise:
- Changing WinRM client settings to enable Basic authentication (or disable negotiation/encryption)
- Connecting via WinRM to another internal system (port 5985)
- Using valid credentials to pivot or drop a malicious service
- Establishing remote command execution via PowerShell or service abuse

---

## Incident Status

**True Positive – Confirmed Lateral Movement via WinRM**

---

## 📁 Remediation & Recommendations

- [x] Disable WinRM on affected endpoints unless required  
- [x] Audit WinRM listener and client config (GPO + Registry)  
- [x] Rotate credentials for CYLOSEC\Administrator  
- [x] Search for matching hashes or command-line patterns across all endpoints  
- [x] Investigate all Event ID 4624 entries with Logon Type 3 or 10  
- [x] Document incident in SOC escalation log and submit to GRC review if required  

---

## Tags

`true-positive` `winrm` `cscript` `lateral-movement` `process-creation` `SOC2` `Sysmon` `T1059.003` `T1021.006`

