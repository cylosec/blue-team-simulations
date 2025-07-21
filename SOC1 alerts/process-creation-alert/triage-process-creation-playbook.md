#  SOC 1 Triage Playbook Example: Suspicious Script Execution (`cscript.exe`)

This playbook outlines how a SOC 1 Analyst should triage a suspicious script execution alert triggered by Wazuh. It follows the standard triage process used in daily alert reviews.

---

##  Alert Overview

- **Agent Name:** `WIN-1T5RE39Q2K5`
- **Agent IP:** `10.0.0.9`
- **User:** `CYLOSEC\\Administrator`
- **Process:** `cscript.exe`
- **Script File:** `winrm.vbs`
- **Parent Process:** `cmd.exe`
- **Integrity Level:** `High`
- **Wazuh Rule ID:** `92032`
- **MITRE Mapping:**
  - `T1059.003` – Command and Scripting Interpreter: Windows Command Shell
  - `T1087` – Account Discovery

---

##  Step 1: Detection

**Log Source:** Wazuh via Sysmon  
**Event ID:** 1 (Process Creation)  
**Rule Triggered:** Suspicious Windows command shell execution  
**Alert Level:** 3 (Informational/Suspicious)

---

##  Step 2: Context Gathering

| Field             | Value                          |
|------------------|---------------------------------|
| Domain User       | CYLOSEC\\Administrator          |
| File Path         | `C:\Users\Administrator\winrm.vbs` |
| Parent Process    | `cmd.exe`                      |
| File Hashes       | MD5, SHA256, IMPHASH available |
| Event Time (UTC)  | `2025-07-10 03:30:55`          |
| Collected By      | Wazuh Agent 005                |

---

##  Step 3: Initial Analysis

**Questions to Ask:**
- Is `winrm.vbs` part of an authorized automation process?
- Was this executed during business hours?
- Is the `Administrator` account typically used for scripting?
- Are there repeated uses of `cscript.exe`, `wscript.exe`, or `powershell.exe`?

---

##  Step 4: Risk Evaluation

**Potential Impact:**
- Modifying **WinRM settings** can enable remote access.
- Use of elevated scripting (`cscript.exe`) may indicate:
  - **Reconnaissance**
  - **Persistence setup**
  - **Lateral movement**

**Indicators of Concern:**
- Admin account used manually
- No associated change request or scheduled task
- Wazuh rule fired **8 times**

---

##  Step 5: Document and Decide

### 🟢 Option 1: False Positive
- Behavior tied to legitimate IT admin automation.
- Execution aligns with internal maintenance SOP.
- Document findings and suppress similar alerts.

###  Option 2: Escalate to SOC 2
- Script origin and purpose unclear.
- Admin usage suspicious or out-of-hours.
- No justification found in ticketing system.
- Escalate for deeper review and threat hunting.

---

##  Notes for SOC 1 Documentation

- **Ticket ID:** _(create or reference existing)_
- **Action Taken:** Initial triage complete
- **Decision:** _False positive_ / _Escalated to SOC 2_
- **Evidence Attached:** Sysmon event, Wazuh alert, timeline, file hash

---

##  Reference

| Framework | ID        | Name                     |
|-----------|-----------|--------------------------|
| MITRE     | T1059.003 | Windows Command Shell    |
| MITRE     | T1087     | Account Discovery        |

# Lateral Movement Evaluation – `cscript.exe` and WinRM Script Execution

This document evaluates whether the suspicious process execution involving `cscript.exe` and `winrm.vbs` on `WIN-1T5RE39Q2K5` represents lateral movement activity or preparation.

---

## Technical Summary

- **User:** CYLOSEC\Administrator
- **Process:** `cscript.exe` (via `cmd.exe`)
- **Script File:** `winrm.vbs`
- **Host IP:** 10.0.0.9
- **Privilege Level:** High (Administrator)
- **Rule Triggered:** Wazuh Rule ID 92032 – Suspicious cmd.exe shell execution
- **Purpose of Script:** Modifies WinRM (Windows Remote Management) settings

---

## Lateral Movement Indicators Checklist

| Indicator | Observed | Details |
|----------|----------|---------|
| Use of a privileged account | Yes | Administrator account used |
| Modification of remote access protocols | Yes | `winrm.vbs` alters WinRM authentication |
| Use of scripting or CLI | Yes | `cscript.exe` executed via `cmd.exe` |
| Outbound WinRM or remote target access | No | No evidence of remote sessions from this alert |
| Credential dumping or impersonation | No | No signs of `lsass`, `mimikatz`, or token abuse |
| Admin share or file transfer activity | No | No `net use` or file copy across hosts observed |
| Login sequence across multiple hosts | No | No correlated 4624 login events across endpoints |

---

## Analysis

### Indicators Suggesting Lateral Movement *Preparation*:
- WinRM is a common tool used in lateral movement (T1021.006).
- Elevated scripting via `cscript.exe` aligns with automation or command-line administration.
- Administrator account used, increasing potential for domain-wide access.

### Missing Evidence to Confirm Lateral Movement:
- No outbound connections, remote logins, or multi-host command execution.
- No credential harvesting or token manipulation events detected.

---

## Conclusion

This activity represents **potential lateral movement preparation** but **does not confirm** lateral movement by itself.

Treat as a **suspicious configuration change** pending additional correlation.

---

## Recommended SOC Follow-up

1. **Check WinRM Configuration**
   - Review listeners:  
     `winrm enumerate winrm/config/listener`
   - Confirm if WinRM was enabled or altered recently.

2. **Correlate Login Events**
   - Search for Event ID `4624` and `4625` around this timestamp.
   - Look for remote logins from this host to other endpoints.

3. **Search for Related Remote Execution Techniques**
   - WMI, PowerShell Remoting, PsExec, or RDP activity.
   - MITRE Techniques to investigate:
     - T1021.006 – Remote Services: WinRM
     - T1028 – Remote Desktop Protocol
     - T1059 – Command and Scripting Interpreter

4. **Determine Business Justification**
   - Check if the action aligns with documented IT automation or scheduled task.
   - If undocumented and unjustified, escalate to SOC 2 for deeper investigation.

---

## Status

- **Triage Owner:** SOC 1 Analyst
- **Escalation Status:** Pending – Based on correlation results
- **Documentation:** Saved in alert ticket with timeline and event artifacts



---

**Status:**  Under Review by SOC 1  
**Next Step:** Monitor similar activity or escalate if confirmed unauthorized.

