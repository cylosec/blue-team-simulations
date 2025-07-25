# SOC2 Alert Investigation: mscorsvw.exe PowerShell DLL Load (Sysmon EID 7)

**Alert ID:** 92151  
**Host:** WIN-1T5RE39Q2K5  
**Date:** 2025-07-20  
**Tactic:** Execution  
**Technique:** T1059.001 – PowerShell  
**Detection Source:** Sysmon Event ID 7  
**Detection Rule:** Binary loaded PowerShell automation library – Possible unmanaged PowerShell execution by suspicious process  
**Severity:** 12 (High)  
**Initial Triage:** SOC1  
**Escalation:** SOC2 for further validation

This folder contains the complete investigation of a Wazuh alert triggered by the .NET optimization service `mscorsvw.exe` loading the `System.Management.Automation.ni.dll` PowerShell DLL. The event raised suspicion due to its unsigned nature and the elevated execution context (NT AUTHORITY\SYSTEM). This was escalated from SOC1 to SOC2 for full validation.
