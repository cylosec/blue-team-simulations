# Detecting Command-and-Control (C2) Activity via Packet Analysis

## Objective

To identify signs of active or attempted C2 communication between a compromised internal host and an external server by analyzing full packet capture (PCAP) data. This may be used as a training guide for SOC1 analysts transitioning to SOC2 roles.

---

## C2 Detection Procedures Using Wireshark

### 1. Identify DNS Resolution to Suspicious Domains

- Apply filter: `dns`
- Look for queries to non-corporate, algorithmically-generated, or newly-registered domains.
- Example detected:  
  `c2-stage.cylosec-breach.com` resolved by host `192.168.1.12` to IP `185.199.111.29`.

**Indicator:** C2 frameworks often use DNS for dynamic infrastructure resolution.

---

### 2. Monitor Connections to External IPs over Non-Standard Ports

- Apply filter:  
  `ip.addr == 185.199.111.29 && tcp.port == 8081`
- Observe outbound connections from internal host.
- Port 8081 is uncommon for normal web activity and should be reviewed.

**Indicator:** Outbound connections to rare ports are a hallmark of C2 tunnels or staged payload delivery.

---

### 3. Detect Beaconing Behavior (Repetitive Timing)

- Examine timestamps of HTTP POST requests.
- Look for repeating requests at consistent intervals (e.g., every 30 seconds).
- Example seen in PCAP: 3 consecutive POST requests with same payload size and interval.

**Indicator:** Automated beaconing used for initial callback or polling by malware.

---

### 4. Analyze HTTP Method and Payload

- Apply filter: `tcp.port == 8081` and right-click → "Follow TCP Stream"
- Look for:
  - POST request to `/stage1.php`
  - Encoded or structured payload (e.g., `user=data&payload=beaconing-pattern`)
  - Lack of browser headers (no User-Agent, Referrer, or Cookies)

**Indicator:** POST method with minimal headers often indicates scripted C2 traffic instead of human interaction.

---

### 5. Correlate with Endpoint Activity

- Use alert timestamps to confirm:
  - Remote command execution (`wmic.exe` → `powershell.exe`)
  - External communication initiated after lateral movement
  - Sysmon process creation logs matching source IP of POST packets

**Indicator:** Lateral movement followed by outbound communication is a strong signal of post-exploitation and staging.

---

## Conclusion: Was C2 Confirmed?

Yes. The following elements validate that C2 activity occurred:

- Internal host resolved a known malicious domain
- Outbound connection to that domain's resolved IP on TCP port 8081
- Regular HTTP POSTs indicative of beaconing
- Payload consistent in size, with structured key-value pairs
- No legitimate service justification for this traffic

Together, these observations confirm that the alert **SIM-002** represents **true positive C2 communication** and justifies full incident response procedures.

---

## Detection Recommendations

- Create detection logic in SIEM for repetitive outbound POST requests to rare IPs/domains
- Monitor DNS queries for known malicious domains
- Flag traffic to external hosts over uncommon TCP ports (e.g., 8081, 8443, 53 if not DNS)
- Enrich with threat intelligence (IP/domain reputation)

