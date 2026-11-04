#!/usr/bin/env bash
# Meshlet dataplane throughput baseline (lane/dataplane-speed).
#
# Builds throwaway network namespaces and measures three paths with iperf3:
#
#   [relay]  client A -> hub -> client B  (hub-and-spoke, kernel forwarding in
#            the hub netns — the shape of Meshlet's default relay path);
#   [direct] client A -> client B         (direct /32 WireGuard peer over the
#            same LAN underlay — the shape `apps/agent/src/direct.rs` promotes);
#   [bare]   plain WireGuard pair         (back-to-back veth, no bridge, no hub
#            — control: proves Meshlet adds no per-packet data-plane overhead).
#
# Variants per scenario: TCP 1 stream, TCP 4 streams, UDP 1 Gbit/s. Optionally
# re-runs the whole matrix with a jumbo underlay (MTU 9000 / tunnel 8920) and
# with all veth offloads off, to quantify both tuning knobs.
#
# Topology pitfalls encoded here were all hit for real (see
# crates/meshlet-network/tests/wg_forwarding.rs header + lane work notes):
# - underlay is an L2 bridge star (host-side veth routing needs host forwarding);
# - a bare pair must move BOTH veth ends into their own netns (host netns
#   between two veth ends silently drops L2 ARP / needs ip_forward);
# - `wg set` (never `setconf`), private-key and peers in separate calls;
# - peer endpoints point at the ns-side veth addresses.
# Offloads: unlike the wg_forwarding.rs note, on this kernel (7.0.0-38) WG
# handshakes succeed with GRO/GSO/TSO on — verified, and throughput roughly
# doubles with them on. The script therefore runs offload-ON by default and
# OFFLOADS=off re-runs everything with them disabled for the A/B comparison.
#
# Requirements: passwordless sudo, wg, iperf3, ethtool. Cleans up on exit.
# Usage: sudo scripts/bench-dataplane.sh [DURATION] [JUMBO] [OFFLOADS]
#   DURATION  iperf3 seconds per run (default 8)
#   JUMBO     1 = also run the matrix at underlay MTU 9000 / tunnel 8920
#   OFFLOADS  1 = also run the matrix with gro/gso/tso/rx/tx/sg off
set -u
DURATION=${1:-8}
JUMBO=${2:-1}
OFFLOADS=${3:-1}
P=mltb
OVERLAY=10.240.0.0/16

if [ "$(id -u)" -eq 0 ]; then SUDO=(); else SUDO=(sudo -n); fi
need() { command -v "$1" >/dev/null || { echo "SKIP: $1 not installed"; exit 0; }; }
need ip; need wg; need iperf3; need ethtool
"${SUDO[@]}" true || { echo "SKIP: passwordless sudo unavailable"; exit 0; }
"${SUDO[@]}" modprobe wireguard 2>/dev/null; [ -d /sys/module/wireguard ] || { echo "SKIP: wireguard module"; exit 0; }

cleanup() {
  for ns in "$P"a "$P"b "$P"h "$P"p "$P"q; do "${SUDO[@]}" ip netns del "$ns" 2>/dev/null; done
  for l in "$P"a0 "$P"a1 "$P"b0 "$P"b1 "$P"h0 "$P"h1 "$P"br0 "$P"pa "$P"pb; do
    "${SUDO[@]}" ip link del "$l" 2>/dev/null
  done
}
trap cleanup EXIT
cleanup

# ---- host CPU sampler: prints busy% across all cores over a window ----
SAMPLE_PID=
start_cpu() {
  (
    while :; do
      grep '^cpu ' /proc/stat | awk '{t=0;i=0;idle=$5+$6;for(i=2;i<=8;i++)t+=$i;print t, idle}' >> /tmp/mltb-cpu.log
      sleep 1
    done
  ) &
  SAMPLE_PID=$!
  : > /tmp/mltb-cpu.log
}
stop_cpu() { # echoes busy% over the sampling window
  kill "$SAMPLE_PID" 2>/dev/null; wait "$SAMPLE_PID" 2>/dev/null
  awk 'NR==1{t0=$1;i0=$2} {t=$1;i=$2} END{d=t-t0;di=i-i0;n=14;printf "  host_busy(14 cores): %.1f%%\n", 100*(1-di/d)}' /tmp/mltb-cpu.log
}

# ---- node helper ----
node_ns() { # NAME UNDERLAY_IP BRIDGE(0/1) -> creates netns+veth (+bridge attach)
  local name=$1 uip=$2 bridge=$3
  "${SUDO[@]}" ip netns add "$P$name"
  if [ "$bridge" = 1 ]; then
    "${SUDO[@]}" ip link add "$P${name}0" type veth peer name "$P${name}1"
    "${SUDO[@]}" ip link set "$P${name}1" netns "$P$name"
    "${SUDO[@]}" ip link set "$P${name}0" master "$P"br0
    "${SUDO[@]}" ip link set "$P${name}0" up
  else
    "${SUDO[@]}" ip link add "$P${name}1" type veth peer name "$P${name}9"
  fi
  "${SUDO[@]}" ip netns exec "$P$name" ip addr add "$uip" dev "$P${name}1"
  "${SUDO[@]}" ip netns exec "$P$name" ip link set "$P${name}1" up
  "${SUDO[@]}" ip netns exec "$P$name" ip link set lo up
}

set_offloads() { # NS DEV on|off
  local ns=$1 dev=$2 mode=$3 f
  for f in gro gso tso rx tx sg; do
    "${SUDO[@]}" ip netns exec "$P$ns" ethtool -K "$dev" "$f" "$mode" >/dev/null 2>&1
  done
}

wait_handshake() { # NS TARGET_IP
  local i
  for i in $(seq 1 15); do
    if "${SUDO[@]}" ip netns exec "$P$1" ping -c1 -W1 "$2" >/dev/null 2>&1; then return 0; fi
  done
  echo "FAIL: handshake/first ping did not complete in $P$1 -> $2"; return 1
}

run_matrix() { # CLIENT_NS SERVER_NS SERVER_OVERLAY_IP LABEL
  local cns=$1 sns=$2 tgt=$3 label=$4
  "${SUDO[@]}" ip netns exec "$P$sns" pkill iperf3 2>/dev/null
  "${SUDO[@]}" ip netns exec "$P$sns" iperf3 -s -1 -D >/dev/null 2>&1
  local out
  echo "[$label] TCP 1 stream:"
  start_cpu
  out=$("${SUDO[@]}" ip netns exec "$P$cns" iperf3 -c "$tgt" -t "$DURATION" -O 1 2>&1)
  echo "$out" | grep -E '^\[\s*[0-9]+\].*(sender|receiver)' | sed 's/^/  /'
  echo "$out" | grep -oE '[0-9]+ sender' >/dev/null
  stop_cpu
  echo "[$label] TCP 4 streams:"
  "${SUDO[@]}" ip netns exec "$P$sns" iperf3 -s -1 -D >/dev/null 2>&1
  start_cpu
  out=$("${SUDO[@]}" ip netns exec "$P$cns" iperf3 -c "$tgt" -t "$DURATION" -P 4 -O 1 2>&1)
  echo "$out" | grep -E '^\[SUM\].*(sender|receiver)' | sed 's/^/  /'
  echo "$out" | grep -oE '[0-9]+ retries' | sed 's/^/  retries: /'
  stop_cpu
  echo "[$label] UDP 1 Gbit/s:"
  "${SUDO[@]}" ip netns exec "$P$sns" iperf3 -s -1 -D >/dev/null 2>&1
  start_cpu
  out=$("${SUDO[@]}" ip netns exec "$P$cns" iperf3 -c "$tgt" -u -b 1g -t "$DURATION" -O 1 2>&1)
  echo "$out" | grep -E '^\[\s*[0-9]+\].*(sender|receiver)' | sed 's/^/  /'
  stop_cpu
}

echo "== environment =="
echo "kernel: $(uname -r)  cpus: $(nproc)  model: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
echo "virt: $(systemd-detect-virt 2>/dev/null || echo unknown)  iperf3: $(iperf3 --version | head -1)"
echo "date: $(date -Is)"

run_mode() { # UNDERLAY_MTU TUNNEL_MTU OFFLOAD_MODE TAG
  local umtu=$1 wmtu=$2 offmode=$3 tag=$4
  echo
  echo "==== mode: underlay_mtu=$umtu tunnel_mtu=$wmtu offloads=$offmode ($tag) ===="

  # --- bridge star: hub + A + B
  "${SUDO[@]}" ip link add "$P"br0 type bridge
  "${SUDO[@]}" ip link set "$P"br0 up mtu "$umtu"
  node_ns a "10.99.0.20/24" 1
  node_ns b "10.99.0.30/24" 1
  node_ns h "10.99.0.10/24" 1
  # bridge ports (host-side veth ends) must carry the underlay MTU too: the
  # bridge drops frames larger than the smallest port (hit for real in the
  # first jumbo run — handshake passed but every 8920B frame vanished).
  for dev in "$P"a0 "$P"b0 "$P"h0; do "${SUDO[@]}" ip link set "$dev" mtu "$umtu"; done
  "${SUDO[@]}" ip netns exec "$P"a ip link set "$P"a1 mtu "$umtu"
  "${SUDO[@]}" ip netns exec "$P"b ip link set "$P"b1 mtu "$umtu"
  "${SUDO[@]}" ip netns exec "$P"h ip link set "$P"h1 mtu "$umtu"
  set_offloads a "$P"a1 "$offmode"; set_offloads b "$P"b1 "$offmode"; set_offloads h "$P"h1 "$offmode"
  # host-side bridge ports too (netns side of veth covers the ns end)
  for dev in "$P"a0 "$P"b0 "$P"h0; do
    for f in gro gso tso rx tx sg; do "${SUDO[@]}" ethtool -K "$dev" "$f" "$offmode" >/dev/null 2>&1; done
  done

  local KA KA_PUB KB KB_PUB KH KH_PUB
  KA=$(wg genkey); KA_PUB=$(printf %s "$KA" | wg pubkey)
  KB=$(wg genkey); KB_PUB=$(printf %s "$KB" | wg pubkey)
  KH=$(wg genkey); KH_PUB=$(printf %s "$KH" | wg pubkey)

  # --- wg interfaces
  "${SUDO[@]}" ip netns exec "$P"h bash -c \
    "ip link add wg0 type wireguard && ip addr add 10.240.0.1/16 dev wg0 && ip link set wg0 up mtu $wmtu \
     && wg set wg0 listen-port 15280 private-key <(echo '$KH') \
     && wg set wg0 peer $KA_PUB allowed-ips 10.240.0.2/32 \
     && wg set wg0 peer $KB_PUB allowed-ips 10.240.0.3/32"
  "${SUDO[@]}" ip netns exec "$P"h sysctl -w net.ipv4.ip_forward=1 >/dev/null
  "${SUDO[@]}" ip netns exec "$P"a bash -c \
    "ip link add wg0 type wireguard && ip addr add 10.240.0.2/16 dev wg0 && ip link set wg0 up mtu $wmtu \
     && wg set wg0 listen-port 15281 private-key <(echo '$KA') \
     && wg set wg0 peer $KH_PUB allowed-ips $OVERLAY endpoint 10.99.0.10:15280 persistent-keepalive 2"
  "${SUDO[@]}" ip netns exec "$P"b bash -c \
    "ip link add wg0 type wireguard && ip addr add 10.240.0.3/16 dev wg0 && ip link set wg0 up mtu $wmtu \
     && wg set wg0 listen-port 15282 private-key <(echo '$KB') \
     && wg set wg0 peer $KH_PUB allowed-ips $OVERLAY endpoint 10.99.0.10:15280 persistent-keepalive 2"

  wait_handshake a 10.240.0.1 || exit 1
  wait_handshake b 10.240.0.1 || exit 1

  run_matrix a b 10.240.0.3 "relay mtu=$wmtu off=$offmode"

  # --- direct peers (mirrors DirectManager::Promote): /32 allowed-ips + LAN endpoint
  "${SUDO[@]}" ip netns exec "$P"a bash -c \
    "wg set wg0 peer $KB_PUB allowed-ips 10.240.0.3/32 endpoint 10.99.0.30:15282 persistent-keepalive 2"
  "${SUDO[@]}" ip netns exec "$P"b bash -c \
    "wg set wg0 peer $KA_PUB allowed-ips 10.240.0.2/32 endpoint 10.99.0.20:15281 persistent-keepalive 2"
  wait_handshake a 10.240.0.3 || exit 1
  run_matrix a b 10.240.0.3 "direct mtu=$wmtu off=$offmode"

  # --- bare pair control (back-to-back veth, both ends in their own netns)
  "${SUDO[@]}" ip netns add "$P"p; "${SUDO[@]}" ip netns add "$P"q
  "${SUDO[@]}" ip link add "$P"pa type veth peer name "$P"pb
  "${SUDO[@]}" ip link set "$P"pa netns "$P"p; "${SUDO[@]}" ip link set "$P"pb netns "$P"q
  "${SUDO[@]}" ip netns exec "$P"p ip addr add 10.98.0.1/30 dev "$P"pa
  "${SUDO[@]}" ip netns exec "$P"p ip link set "$P"pa up mtu "$umtu"
  "${SUDO[@]}" ip netns exec "$P"p ip link set lo up
  "${SUDO[@]}" ip netns exec "$P"q ip addr add 10.98.0.2/30 dev "$P"pb
  "${SUDO[@]}" ip netns exec "$P"q ip link set "$P"pb up mtu "$umtu"
  "${SUDO[@]}" ip netns exec "$P"q ip link set lo up
  local KC KC_PUB KD KD_PUB
  KC=$(wg genkey); KC_PUB=$(printf %s "$KC" | wg pubkey)
  KD=$(wg genkey); KD_PUB=$(printf %s "$KD" | wg pubkey)
  "${SUDO[@]}" ip netns exec "$P"p bash -c \
    "ip link add wg0 type wireguard && ip addr add 10.240.0.20/24 dev wg0 && ip link set wg0 up mtu $wmtu \
     && wg set wg0 listen-port 15291 private-key <(echo '$KC') \
     && wg set wg0 peer $KD_PUB allowed-ips $OVERLAY endpoint 10.98.0.2:15292"
  "${SUDO[@]}" ip netns exec "$P"q bash -c \
    "ip link add wg0 type wireguard && ip addr add 10.240.0.21/24 dev wg0 && ip link set wg0 up mtu $wmtu \
     && wg set wg0 listen-port 15292 private-key <(echo '$KD') \
     && wg set wg0 peer $KC_PUB allowed-ips $OVERLAY endpoint 10.98.0.1:15291"
  wait_handshake p 10.240.0.21 || exit 1
  run_matrix p q 10.240.0.21 "bare mtu=$wmtu off=$offmode"

  cleanup
}

rm -f /tmp/mltb-cpu.log
run_mode 1500 1420 on "Meshlet defaults"
[ "$JUMBO" = 1 ] && run_mode 9000 8920 on "jumbo underlay"
[ "$OFFLOADS" = 1 ] && run_mode 1500 1420 off "offloads disabled"
echo
echo "== done (all netns/veth/bridge removed by trap) =="
