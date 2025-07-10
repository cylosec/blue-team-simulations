# JSON Alert Breakdown: Sysmon Event ID 1 (Process Creation)

This document explains how to interpret a JSON alert from Wazuh involving Sysmon Event ID 1. This particular event captures a process creation, which is critical for detecting suspicious execution behavior.

---

## 1. `"_source.agent"`

### Agent Metadata

```json
"agent": {
  "ip": "10.0.0.9",
  "name": "WIN-1T5RE39Q2K5",
  "id": "005"
}
```

* **IP**: The endpoint’s internal IP address.
* **Name**: Hostname where the alert originated.
* **ID**: Unique identifier for the Wazuh agent.

---

## 2. `"_source.data.win.eventdata"`

### Process Execution Details

```json
"eventdata": {
  "image": "C:\\Windows\\System32\\cscript.exe",
  "commandLine": "cscript  //nologo \\\"C:\\\\Windows\\\\System32\\\\winrm.vbs\\\" ..."
}
```

* **Image**: Full path to the process that was created.
* **CommandLine**: Command used to launch the process.
* **ParentImage**: The parent process (e.g., `cmd.exe`).
* **IntegrityLevel**: Indicates privilege level (e.g., High = admin).
* **User**: The account that ran the process.

---

## 3. `"_source.data.win.system"`

### Sysmon Metadata

```json
"system": {
  "eventID": "1",
  "channel": "Microsoft-Windows-Sysmon/Operational",
  "computer": "WIN-1T5RE39Q2K5.cylosec.local",
  "providerName": "Microsoft-Windows-Sysmon"
}
```

* **eventID 1**: Identifies this as a process creation event.
* **Channel**: Log source — from Sysmon's operational logs.
* **Computer**: FQDN of the machine.
* **Provider**: Confirms Sysmon as the event generator.

---

## 4. `"_source.rule"`

### Detection Rule Triggered

```json
"rule": {
  "description": "Suspicious Windows cmd shell execution",
  "level": 3,
  "mitre": {
    "technique": ["Account Discovery", "Windows Command Shell"],
    "id": ["T1087", "T1059.003"],
    "tactic": ["Discovery", "Execution"]
  }
}
```

* **Description**: The detection rule fired by Wazuh.
* **Level**: Rule severity (e.g., 3 = suspicious).
* **MITRE Techniques**:

  * `T1059.003`: Command-line execution (e.g., cmd.exe, cscript)
  * `T1087`: Account Discovery
* **Tactics**:

  * `Execution`: The act of running code.
  * `Discovery`: Reconnaissance inside the network.

---

## 5. `"_source.timestamp"`

### Alert Time

```json
"timestamp": "2025-07-10T03:31:55.385Z"
```

* ISO 8601 timestamp of when the alert was logged by Wazuh.

---

## Summary

This alert shows that `cscript.exe` was executed using elevated privileges from `cmd.exe` to modify `winrm` settings. While this can be legitimate, it's often seen in post-exploitation activity and lateral movement setup.

---

## SOC 1 Analyst Actions

1. Validate whether this command is part of a known script or task.
2. Investigate recent logon sessions by the Administrator.
3. Check if similar commands have executed on other endpoints.
4. Escalate to SOC 2 for hunting if part of broader attack pattern.

