# Snort: DHCP Option 52 (Overload) Detection Gap — Hidden Option Injection via sname/file Fields

## 1. Summary

DHCP Option 52 (Option Overload, RFC 2131 §4.1) instructs clients to parse the BOOTP `sname` (64 bytes) and/or `file` (128 bytes) header fields as additional DHCP option areas. An attacker can use this mechanism to deliver critical network configuration (DNS server, default gateway, domain name) in the `sname`/`file` fields while the standard DHCP options area remains benign-looking.

Current Snort DHCP inspection rules examine the standard options area of DHCP packets. When Option 52 is present and options are encoded in `sname`/`file`, those options are not covered by existing detection logic. This creates a blind spot where an attacker can perform DNS hijacking, gateway hijacking, and domain spoofing via DHCP without triggering DHCP-related alerts.

This has been verified: BusyBox udhcpc 1.36.1 fully parses and applies options from overloaded sname, writing attacker-controlled DNS, router, and domain to system configuration.

## 2. The Detection Gap

### 2.1 Normal DHCPACK (detected by Snort)

```
Standard Options Area:
  Option 53 = ACK
  Option 6  = DNS Server (inspectable)
  Option 3  = Router (inspectable)
  Option 15 = Domain Name (inspectable)

sname field: "tftp-server" (normal hostname, not parsed as options)
```

Snort can inspect Options 6, 3, 15 in the standard area.

### 2.2 Option Overload DHCPACK (not detected by Snort)

```
Standard Options Area:
  Option 53 = ACK
  Option 54 = Server ID
  Option 51 = Lease Time
  Option 1  = Subnet Mask
  Option 52 = 2 (sname contains options)
  ← No DNS, no router, no domain here

sname field (parsed as options by client):
  Option 6  = Attacker DNS        ← hidden from Snort
  Option 3  = Attacker Router     ← hidden from Snort
  Option 15 = evil.corp           ← hidden from Snort
  Option 255 = End
```

The standard options area contains no DNS server, no router, no domain — it appears incomplete but not malicious. The actual malicious configuration is in the `sname` field, which Snort does not currently parse as an options area even when Option 52 signals it should be.

## 3. Verified Attack Results

### Test Environment

- Rogue DHCP server: Scapy (Python 3), crafted DHCPACK with Option 52 = 2
- Victim: BusyBox udhcpc 1.36.1 (Alpine 3.19)
- Network: Docker bridge 10.100.0.0/24

### Client Applied Configuration

```
[udhcpc-script]   Router:  10.100.0.2       ← from overloaded sname
[udhcpc-script]   DNS:     10.100.0.2       ← from overloaded sname
[udhcpc-script]   Domain:  evil.corp        ← from overloaded sname

$ cat /etc/resolv.conf
search evil.corp
nameserver 10.100.0.2
```

The client accepted and applied DNS server, router, and domain name from the overloaded `sname` field. No corresponding options existed in the standard options area.

## 4. Impact

An attacker can perform:
- DNS hijacking (all name resolution routed to attacker)
- Gateway hijacking (all traffic intercepted via MitM)
- Domain suffix spoofing (short hostname phishing)

All delivered through a mechanism invisible to current Snort DHCP inspection.

## 5. Proposed Detection Rules

### Rule 1: Alert on any DHCPACK/DHCPOFFER containing Option 52

Option 52 (0x34) is extremely rare in legitimate modern DHCP deployments. Its presence in a DHCP response should be treated as suspicious.

```
# Snort 3 rule: detect Option 52 in DHCP server responses
# DHCP magic cookie (0x63825363) at BOOTP offset 236, then search for Option 52 (0x34) with length 1
alert udp any 67 -> any 68 (
    msg:"DHCP Option Overload (Option 52) detected in server response";
    content:"|63 82 53 63|", offset 236, depth 4;
    content:"|34 01|", distance 0;
    metadata:policy security-ips alert;
    classtype:policy-violation;
    sid:1000001; rev:1;
)
```

### Rule 2: Alert on DHCPACK with Option 52 and no DNS/Router in standard options

This detects the specific evasion pattern: Option 52 present but critical options missing from the standard area (suggesting they are hidden in sname/file).

```
# Snort 3 rule: DHCPACK with Option 52 but no Option 6 (DNS) in standard options
# This is the high-confidence evasion indicator
alert udp any 67 -> any 68 (
    msg:"DHCP Overload evasion: Option 52 present, DNS option absent from standard area";
    content:"|63 82 53 63|", offset 236, depth 4;
    content:"|34 01|", distance 0;
    content:!"|06|", distance 0;
    metadata:policy security-ips alert;
    classtype:attempted-admin;
    sid:1000002; rev:1;
)
```

### Longer-Term Recommendation

For comprehensive coverage, Snort's DHCP preprocessor/inspector should be extended to:
1. Check for Option 52 in DHCP responses
2. When Option 52 is present, parse the `sname` and/or `file` fields as additional options areas
3. Apply existing DHCP option inspection rules to the extracted options
4. Raise an alert when Option 52 is encountered (given its rarity in practice)

## 6. Reproduction

The PoC can be used to verify the detection gap and test proposed rules.

### Steps

```bash
docker compose up -d

docker cp DHCPOFFER_sname_response/rogue_sname_server.py \
    rogue-dhcp-server:/poc/

# Start Snort monitoring on the test network interface (setup-dependent)

# Launch rogue server with Option Overload
docker exec rogue-dhcp-server bash -c \
    'cd /poc && python3 rogue_sname_server.py 20 10.100.0.2 B' &
sleep 3

# Trigger DHCP on victim
docker exec client-udhcpc sh -c \
    'ip addr flush dev eth0 && udhcpc -i eth0 -f -v -S -O search -n -q'

# Verify: client applied attacker config, Snort did not alert (without proposed rules)
docker exec client-udhcpc cat /etc/resolv.conf
```

### Files

| File | Description |
|------|-------------|
| `rogue_sname_server.py` | Scapy-based rogue server generating Option Overload DHCPACK |
| `run_poc.sh` | Orchestration script |
| `logs/sname_caseB.pcap` | Packet capture of Option Overload attack |
| `logs/dhcp_caseB.log` | Client output showing applied attacker config |

## 7. References

- RFC 2131 §4.1: Dynamic Host Configuration Protocol — Option Overloading
- RFC 2132 §9.3: DHCP Options — Option 52 (Option Overload)
- CVE-2024-3661: TunnelVision — DHCP Option 121 routing injection (same attack class)
- Snort 3 Documentation: https://docs.snort.org/

## 8. Related Reports

- **This repository**: https://github.com/APEvul-cyber/DHCP_snort_vul
- Verified client-side impact (BusyBox udhcpc): https://github.com/APEvul-cyber/DHCP_busybox_vul
- Same detection gap — Suricata: https://github.com/APEvul-cyber/DHCP_suricata_vul
