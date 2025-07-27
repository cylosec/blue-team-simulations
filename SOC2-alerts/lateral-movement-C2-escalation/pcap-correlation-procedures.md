# PCAP Correlation Procedures – Wireshark Analysis

## Objective

This procedure outlines how to use Wireshark to validate the network behavior associated with lateral movement and command-and-control (C2) activity identified in alert `SIM-002-LATMOV-C2`.

---

## Step 1: Load and Inspect the PCAP

- Open `packet-capture.pcap` in Wireshark.
- Apply filters to reduce noise:
  - `ip.addr == 185.199.111.29`
  - `tcp.port == 8081`
  - `dns.qry.name == "c2-stage.cylosec-breach.com"`

---

## Step 2: Analyze DNS Resolution

### Purpose
Confirm that the internal host resolved a suspicious domain to an external IP before beaconing.

### Filter
```plaintext
dns
