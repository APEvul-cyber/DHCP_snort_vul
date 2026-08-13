# Snort 3: DHCP Option 52 (`sname`/`file`) not inspected

**Affected:** Snort 3 DHCP inspection.  
**CWE:** CWE-693

RFC 2131: Option 52 means extra options live in BOOTP `sname` and/or `file`. BusyBox udhcpc applies them.

Snort rules that match Option 6/3/15 after the magic cookie do not see values stored only in `sname`. The options area can look harmless.

This is a parser coverage gap, not a Snort crash.

## Reproduce

DHCPACK: Option 52=2; DNS/router/domain only in `sname`. Client applies them. See `rogue_sname_server.py` mode B and `sname_caseB.pcap` from the client report.

**Expected:** parse overload fields; alert on Option 52 (rare in modern nets).

## References

- RFC 2131 §4.1
- https://github.com/APEvul-cyber/DHCP_busybox_vul
- https://github.com/APEvul-cyber/DHCP_snort_vul/tree/main/option-52-gap