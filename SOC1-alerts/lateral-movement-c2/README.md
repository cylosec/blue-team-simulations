# SIM-002: Lateral Movement and Command-and-Control (C2) Beaconing

## Overview

This simulation replicates a real-world scenario where an attacker gains an initial foothold on a compromised host and then performs **lateral movement** via WMI. The attacker then establishes **Command-and-Control (C2)** communication to an external IP using an uncommon port (TCP/8081), with indications of possible data exfiltration.

This scenario is mapped to **MITRE ATT&CK techniques** and is designed to be used in SOC Level 2 alert triage and incident response workflows.

---

## Scenario Summary

| Component           | Detail                                             |
|---------------------|-----------------------------------------------------|
| Initial Access      | PowerShell payload (encoded)                        |
| Lateral Movement    | WMI execution targeting remote host (192.168.1.12) |
| C2 Activity         | Outbound TCP traffic to external IP (185.199.111.29:8081) |
| Protocols Observed  | DNS, TCP (8081), SMB                                |
| Detection Tools     | Sysmon, Wazuh, Wireshark                            |
| Status              | Escalated for SOC2-level investigation              |

---

## Contents

- `alert.json` – Simulated Wazuh alert in JSON format
- `packet-capture.pcap` – PCAP showing DNS resolution and C2 beaconing
- `investigation-notes.md` – Analyst notes and timeline of events
- `mitre-mapping.md` – ATT&CK technique references for blue team alignment
- `jira-ticket-template.md` – Example SOC2 incident response ticket template

---

## Objectives

- Train SOC analysts to identify signs of lateral movement
- Analyze outbound beaconing to detect early-stage C2 activity
- Practice mapping detections to MITRE ATT&CK
- Correlate telemetry from host (Sysmon) and network (Wireshark)

---

## Key MITRE Techniques

| Tactic              | Technique                        | ID          |
|---------------------|----------------------------------|-------------|
| Lateral Movement    | WMI Remote Execution             | T1021.001   |
| Execution           | PowerShell                       | T1059.001   |
| Command & Control   | Application Layer Protocol: HTTP | T1071.001   |

---

## Suggested Analysis Steps

1. Open `packet-capture.pcap` in Wireshark
2. Filter by:
   - `ip.addr == 185.199.111.29`
   - `tcp.port == 8081`
   - `dns.qry.name == "c2-stage.cylosec-breach.com"`
3. Observe repetitive HTTP POST traffic and payload sizes
4. Review `alert.json` to correlate process tree and user context
5. Review `investigation-notes.md` for timeline and artifacts
6. Initiate containment, eradication, and recovery steps per SOC2 protocol

---

## Intended Use

This simulation is intended for educational and defensive security testing purposes only. It is designed to strengthen blue team capabilities in identifying, correlating, and responding to sophisticated post-exploitation behavior.

---

## Created By
**CyloSec Security Simulations**  
Maintained by: [Your GitHub Handle or Team Name]  
Date: July 2025

