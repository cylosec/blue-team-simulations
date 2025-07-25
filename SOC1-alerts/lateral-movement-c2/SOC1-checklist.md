# SOC1 to SOC2 Escalation Checklist

## Purpose

This checklist outlines the process and criteria used by a SOC Level 1 Analyst to escalate an alert to SOC Level 2. It ensures that escalations are consistent, justified, and include the necessary contextual information for effective incident triage and response.

---

## 1. Alert Validation

- [ ] Confirm alert is not a known false positive or previously suppressed event
- [ ] Cross-check against existing allowlists, maintenance windows, or baselines
- [ ] Verify alert rule severity (e.g., level 10 or higher in Wazuh, Critical in Splunk)
- [ ] Validate time correlation across multiple events
- [ ] Confirm indicators of lateral movement, persistence, privilege escalation, or C2

---

## 2. Host and User Context

- [ ] Identify affected hostname(s), IP address(es), and user accounts
- [ ] Determine whether the user is authorized to perform the flagged action
- [ ] Review login history, location anomalies, or concurrent sessions
- [ ] Check for evidence of process injection, script execution, or LOLBAS use
- [ ] Review recent software installations, group memberships, and privilege changes

---

## 3. Log Correlation and Enrichment

- [ ] Correlate endpoint telemetry (e.g., Sysmon) with network activity (e.g., Zeek, PCAP)
- [ ] Cross-reference with DNS logs, proxy logs, and firewall data
- [ ] Identify any matched IOCs (IP, domain, hash, file path)
- [ ] Validate alerts against threat intel feeds or known malicious infrastructure
- [ ] Check MITRE ATT&CK mappings associated with the observed behavior

---

## 4. Documentation for Escalation

- [ ] Record full alert payload (JSON, raw log, event ID)
- [ ] Document timeline of key events and process chain
- [ ] Capture relevant screenshots or PCAP filters if applicable
- [ ] Summarize analyst findings and reason for escalation
- [ ] Include all supporting artifacts (log excerpts, hashes, URLs, etc.)

---

## 5. Communication and Handoff

- [ ] Assign to SOC2 queue or create a JIRA/incident response ticket
- [ ] Notify SOC2 or IR team via defined escalation channel (e.g., Teams, Slack, PagerDuty)
- [ ] Update ticket with incident priority and urgency level
- [ ] Ensure all linked alerts and artifacts are accessible to the escalation team
- [ ] Continue monitoring for additional correlated alerts during investigation

---

## Notes

Escalation should not rely solely on severity score. Behavioral patterns, context, and corroborating evidence must justify SOC2 involvement. If uncertain, consult shift lead or team lead before escalation.

