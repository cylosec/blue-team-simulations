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

