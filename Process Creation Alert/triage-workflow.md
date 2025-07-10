## Alert Breakdown: Sysmon Event ID 1 - Suspicious Script Execution

### Alert Summary
A process execution was detected on endpoint `WIN-1T5RE39Q2K5` involving the Windows Script Host (`cscript.exe`) used to run a VBScript that modifies WinRM client authentication settings.

---

### Event Metadata

**Agent Details**
- Hostname: `WIN-1T5RE39Q2K5`
- IP Address: `10.0.0.9`
- Agent ID: `005`

**User Context**
- User: `CYLOSEC\Administrator`
- Integrity Level: High
- Terminal Session ID: 2

**Timestamps**
- Event Time (UTC): `2025-07-10 03:30:55.114`
- Ingested by Wazuh: `2025-07-10T03:31:55.385Z`

---

### Process Execution Details

**Parent Process**
- Image: `C:\Windows\System32\cmd.exe`
- Command Line:
