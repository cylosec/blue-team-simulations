# Key Indicators of Malicious Activity and Command-and-Control (C2)

## Host-Based Indicators

| Indicator Type       | Value / Description                                                         | Source               |
|----------------------|------------------------------------------------------------------------------|----------------------|
| Suspicious Process   | `powershell.exe -EncodedCommand ...`                                         | Sysmon Event ID 1    |
| Parent Process       | `wmic.exe` spawning PowerShell on remote system                             | Sysmon Event ID 1    |
| Unusual Process Tree | PowerShell spawned from `wmic.exe` or no legitimate parent                  | Sysmon Logs          |
| User Account         | `cylosec\attacker` – non-standard login hours or abnormal behavior          | Windows Security Log |
| Scheduled Task       | Any persistence method like task creation or autorun registry key           | Windows Event Logs   |

---

## Network-Based Indicators

| Indicator Type       | Value / Description                                                         | Source               |
|----------------------|------------------------------------------------------------------------------|----------------------|
| External IP Address  | `185.199.111.29` – Known malicious infrastructure                           | PCAP / Firewall Logs |
| C2 Domain            | `c2-stage.cylosec-breach.com`                                               | DNS Logs             |
| Outbound Port        | TCP 8081 – uncommon for legitimate outbound web traffic                     | Firewall / PCAP      |
| Beaconing Pattern    | Regular interval HTTP POST requests every 30 seconds                        | Wireshark / PCAP     |
| Data Exfil Pattern   | Repetitive payloads ~10KB, same destination, stable interval                | PCAP                 |
| DNS Activity         | Repeated lookups for `*.cylosec-breach.com`                                 | DNS Logs             |

---

## Behavior-Based Indicators

| Behavior                          | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| Lateral Movement via WMI          | Execution of remote process from WIN-DC01 to WIN-SQL01                     |
| LOLBAS Tool Usage                 | Legitimate Windows binaries used for unauthorized execution (WMIC, PowerShell) |
| No User Interaction               | Processes executed without RDP or logged-in user session                   |
| Anomalous Outbound Traffic        | From internal host to rare external IP or domain over a non-standard port  |
| Lack of Legitimate Referrer Logs | C2 HTTP traffic lacks browser headers or expected session context          |

---

## IOC Summary

```text
IP Address:        185.199.111.29
Domain:            c2-stage.cylosec-breach.com
Process:           powershell.exe -EncodedCommand
Remote Command:    wmic.exe /node:192.168.1.12 process call create ...
Port:              TCP/8081
Protocol:          HTTP POST
Pattern:           Beaconing every 30 seconds, ~10KB payload
