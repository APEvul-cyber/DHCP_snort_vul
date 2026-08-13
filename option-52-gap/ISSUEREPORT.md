# DHCP inspector: Option 52 overload (`sname`/`file`) is not parsed

RFC 2131 Option 52 puts more options in `sname`/`file`. udhcpc applies them. Snort 3 still only looks at the standard options area.

Please parse those fields after Option 52, and consider an event on Option 52 (uncommon).

PoC: `rogue_sname_server.py` mode B.