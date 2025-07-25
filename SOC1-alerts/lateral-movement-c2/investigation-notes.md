# Investigation Notes: SIM-002 – Lateral Movement and C2 Beaconing

## Incident Summary

- **Alert ID:** SIM-002-LATMOV-C2  
- **Date:** July 25, 2025  
- **Analyst:** [Insert Analyst Name]  
- **Ticket ID:** SOC2-IR-2025-74  
- **Severity Level:** High  
- **Status:** Escalated – Active Investigation  
- **Detection Source:** Wazuh SIEM (Sysmon and Network Correlation)  
- **Targeted Hosts:**  
  - WIN-DC01.cylosec.local (192.168.1.10)  
  - WIN-SQL01.cylosec.local (192.168.1.12)  
- **External IP Contacted:** 185.199.111.29 (Resolved from `c2-stage.cylosec-breach.com`)  
- **Relevant Techniques (MITRE ATT&CK):**  
  - T1021.001 (Remote Services: WMI)  
  - T1059.001 (Command Line: PowerShell)  
  - T1071.001 (Application Layer Protocol: Web Traffic)

---

## Timeline of Events

| Timestamp (UTC)        | Event Description                                                                                  |
|------------------------|----------------------------------------------------------------------------------------------------|
| 2025-07-25T14:27:55Z   | Initial PowerShell process executed by user `cylosec\attacker` on WIN-DC01                         |
| 2025-07-25T14:28:05Z   | Suspicious WMI command issued targeting WIN-SQL01: `wmic /node:192.168.1.12 process call create ...` |
| 2025-07-25T14:28:30Z   | New PowerShell instance detected on WIN-SQL01, consistent with lateral execution                   |
| 2025-07-25T14:29:00Z   | Outbound connection from WIN-SQL01 to 185.199.111.29 on TCP port 8081 initiated                    |
| 2025-07-25T14:29:30Z   | DNS query for `c2-stage.cylosec-breach.com` resolved to 185.199.111.29                             |
| 2025-07-25T14:30:15Z   | Beaconing pattern observed (HTTP POST every 30 seconds, static payload size ~10KB)                 |
| 2025-07-25T14:32:11Z   | Wazuh rule triggered and correlated: Process Creation + Network Anomaly + Known IOC match          |
| 2025-07-25T14:33:00Z   | Alert escalated to SOC2 for immediate response and containment                                     |

---

## Observations

- The use of encoded PowerShell and remote WMI process creation indicates a post-exploitation tactic typical of lateral movement.
- The external IP contacted is not in use by any approved service and has a known history of hosting C2 infrastructure.
- Beaconing pattern and unusual port (8081) suggest possible use of a custom or proxy-aware malware.
- The domain `c2-stage.cylosec-breach.com` appears in multiple threat intel feeds as a known IOC.

---

## Recommended Actions

1. Isolate WIN-SQL01 from the network to prevent further C2 communication.
2. Perform memory analysis on both endpoints to recover in-memory payloads and shellcode.
3. Review recent login and authentication events across both endpoints.
4. Initiate IOC sweep across all hosts for signs of `c2-stage.cylosec-breach.com` and similar artifacts.
5. Add the external IP and domain to blocklists at perimeter firewalls and DNS sinkhole.
6. Engage threat intel team for further enrichment and attribution.
7. Document findings and update MITRE mapping in case documentation.

---

## Artifacts Collected

- `alert.json`: Wazuh-generated alert including Sysmon process data and network logs
- `packet-capture.pcap`: Full packet capture of suspicious traffic
- Sysmon event logs from WIN-DC01 and WIN-SQL01
- Screenshot evidence of process trees and raw PowerShell commands

---

## Analyst Notes

- The use of legitimate tools (PowerShell, WMIC) aligns with Living off the Land (LOLBAS) tactics.
- Host telemetry confirmed correlation between process execution and network behavior.
- PCAP review in Wireshark showed consistent beaconing that may indicate an automated C2 framework.
- Lateral movement and beaconing happened within a 6-minute window, indicating a pre-staged payload or automation.

---

## Next Steps

- Continue threat hunting for privilege escalation or credential dumping activity.
- Cross-reference any recent phishing emails or dropped payloads that could have initiated this sequence.
- Review any outbound firewall logs for additional anomalies matching the beaconing behavior.

