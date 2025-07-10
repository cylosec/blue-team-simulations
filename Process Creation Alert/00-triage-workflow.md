# SOC 1 Triage Workflow

This document outlines the step-by-step triage process for a SOC 1 Analyst when responding to alerts in a SIEM platform such as Wazuh. The goal is to quickly assess alerts, determine impact, and take appropriate action or escalation steps.

---

## 1. Alert Ingestion

* SIEM collects and normalizes data from endpoint agents, logs, and sensors.
* Alert is generated based on rule match (e.g., Sysmon Event ID 1, Wazuh rule 92032).

## 2. Initial Alert Review

* Identify alert ID, severity level, and timestamp.
* Check source system (hostname, IP address).
* Determine user context (logged-in user, privileges).
* Review alert message and rule description.

## 3. Classification

* **True Positive**: Legitimate suspicious or malicious activity.
* **False Positive**: Expected behavior, misclassified.
* **Benign True Positive**: Known safe activity that is still technically suspicious.

## 4. Context Enrichment

* Check related events (e.g., parent/child processes, login attempts).
* Use threat intelligence (hash lookups, MITRE mapping).
* Review user and system behavior before and after event.

## 5. Validation

* Cross-reference with asset inventory and change management.
* Confirm if the alert matches a known script, admin tool, or baseline behavior.

## 6. Documentation

* Record triage findings in internal tracking system (e.g., JIRA, ServiceNow).
* Include:

  * Summary of alert
  * User, host, timestamp
  * Steps taken
  * Final verdict (false positive, escalated, resolved)

## 7. Escalation (If Needed)

* Escalate to SOC 2 or Incident Response if:

  * Privileged account misuse
  * Remote execution or lateral movement
  * Malware or persistence technique detected

## 8. Suppression (If Applicable)

* If alert is a repeat false positive:

  * Create exception or tuning rule
  * Document justification for suppression

---

## Summary

The triage workflow is the foundation of efficient SOC operations. It ensures alerts are reviewed consistently and escalated appropriately while minimizing noise through validation and tuning.
