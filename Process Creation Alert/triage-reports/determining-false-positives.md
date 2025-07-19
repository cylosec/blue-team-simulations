# SOC 1: False Positive Indicators Checklist

This checklist helps analysts decide whether an alert should be escalated or closed as a false positive. Use this to standardize triage decisions in your SOC 1 workflow.

---

## 1. Authorized User Context

- [ ] Was the process initiated by a known administrator or service account?
- [ ] Does the alert align with normal working hours for the user?
- [ ] Is the user part of a trusted security group (e.g., Domain Admins)?

---

## 2. Known Baseline Activity

- [ ] Is the command or script part of a documented IT automation process?
- [ ] Does the hash of the binary match a known and signed Microsoft binary?
- [ ] Have we seen this command/process regularly on this system in the past?

---

## 3. System/Process Behavior

- [ ] Is the parent-child process relationship common and expected (e.g., `cmd.exe` spawning `cscript.exe` for a WinRM change)?
- [ ] Is the integrity level expected for the user and action (e.g., High for admin-level scripts)?
- [ ] Does the process path match a signed application or OS location (`C:\Windows\System32\`)?

---

## 4. Threat Intelligence & Signature Context

- [ ] No matching indicators in threat feeds or VirusTotal (for hash/domain/IP)?
- [ ] No overlap with MITRE TTP chains linked to current campaigns?
- [ ] Rule severity is low-to-medium and not part of known attack patterns?

---

## 5. Environmental Context

- [ ] Alert triggered during a patch window or scripted configuration change?
- [ ] Was the endpoint recently imaged or provisioned?
- [ ] Has this alert fired frequently with no impact or correlation?

---

## Escalation Decision Guide

| Condition Met | Action               |
|---------------|----------------------|
| 0–2 checks    | Escalate for review  |
| 3–4 checks    | Investigate further  |
| 5+ checks     | Likely false positive (close with notes) |

---

## Documentation

If determined to be a false positive:
- [ ] Add to False Positive KB
- [ ] Create hash or path suppression rule in Wazuh (with justification)
- [ ] Comment on JIRA ticket with reason and supporting evidence

## Use Case

Detect execution of cscript.exe running winrm.vbs to configure WinRM — often used legitimately in system setup or remotely abused for lateral movement.

## Custom Wazuh Rule (XML)
Place this inside your rules_local.xml (usually in /var/ossec/etc/rules/):

```xml
<group name="winrm_script_exec,sysmon,windows,process_creation">
  <rule id="100120" level="6">
    <if_sid>92032</if_sid> <!-- Base rule: Suspicious Windows cmd shell execution -->
    <field name="win.system.eventID">1</field>
    <field name="win.eventdata.Image">C:\\Windows\\System32\\cscript.exe</field>
    <field name="win.eventdata.CommandLine">.*winrm\.vbs.*</field>
    <description>Execution of WinRM configuration script via cscript.exe (potential lateral movement prep)</description>
    <mitre>
      <id>T1059.003</id> <!-- Command and Scripting Interpreter: Windows Command Shell -->
      <id>T1021.006</id> <!-- Remote Services: Windows Remote Management -->
    </mitre>
    <group>remote_exec,scripting,winrm_monitoring</group>
  </rule>
</group>
```

## Optional: Add Lab Whitelist Rule (Lower Priority)
If this behavior is recurring in your lab, add a second rule to downgrade severity when executed by CYLOSEC\Administrator:

```xml
<rule id="100121" level="2" overwrite="true">
  <if_sid>100120</if_sid>
  <field name="win.eventdata.User">CYLOSEC\\Administrator</field>
  <description>Known lab-based execution of winrm.vbs via cscript.exe (CYLOSEC\\Administrator)</description>
  <group>lab_noise,false_positives</group>
</rule>
```

---

## Reload Wazuh Rules
After saving changes, restart the Wazuh manager to apply:

```bash
sudo systemctl restart wazuh-manager
```
