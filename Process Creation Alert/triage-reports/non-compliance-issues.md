# SOC 1 Triage: Common Non-Compliance Issues

This guide outlines non-compliance issues that may arise during SOC 1 alert triage. These should be documented in JIRA under a "Compliance Notes" section or tracked in compliance reporting.

---

## 1. Unauthorized Use of Admin Accounts

- Executable run by account not approved for admin access
- No documented justification or change request
- Routine use of Domain Admin for scripting or remote changes

**Policy Mapping**:
- NIST 800-53: AC-2, AC-6 (Least Privilege)
- ISO 27001: A.9.2.3 (User Access Rights Review)

---

## 2. Unapproved Script Execution

- Execution of cscript, wscript, PowerShell from temp directories
- Unsigned or undocumented scripts
- Lack of change ticket or peer review

**Policy Mapping**:
- NIST 800-53: CM-5, SI-10
- SOX: Change Management Controls

---

## 3. Improper Remote Configuration

- Use of WinRM or remote shell tools without MFA or logging
- Unauthorized remote admin access from unmanaged endpoints

**Policy Mapping**:
- NIST 800-53: AC-17, AU-12
- ISO 27001: A.12.4.1 (Event Logging)

---

## 4. Lack of Evidence for Scheduled Tasks

- No linked change ticket for maintenance window
- No KB or documentation for script or its owner

**Policy Mapping**:
- NIST 800-53: PL-2, CM-3
- SOC 1 (SSAE 18): Control Monitoring and Environment

---

## 5. Hash or Binary Mismatch

- File hash does not match Microsoft signed binaries
- Failed integrity check but no malware alert

**Policy Mapping**:
- NIST 800-53: SI-7 (Software Integrity)
- PCI-DSS: Requirement 11.5.2 (File Integrity Monitoring)

---

## JIRA Example Snippet

```markdown
**Compliance Notes**

- [ ] No documented change control record for WinRM configuration
- [ ] Script executed by Domain Admin during off-hours
- [ ] Hash matches signed Microsoft binary (low risk)
- [ ] Recommend control update: script documentation required for WinRM edits

Policy References:
- NIST 800-53: AC-6, CM-5
- SOC 1: Control Monitoring, Least Privilege
```

---

## Use Case

Add this document to your GitHub `SOC1/Compliance/` folder as a reference for blue team triage and audit preparation.
