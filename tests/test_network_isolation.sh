#!/usr/bin/env bash
# Proves the infra-level isolation guarantee for SENTINEL LAB:
# containers on attacker_net/target_net (Docker networks with `internal: true`)
# cannot reach anything outside the compose network, while they CAN reach
# each other. This must pass before any other stage of the lab is trusted.
set -uo pipefail

cd "$(dirname "$0")/.."
COMPOSE="docker compose"
FAIL=0

echo "== SENTINEL LAB :: network isolation self-test =="

$COMPOSE --profile isolation-test build isolation-attacker >/dev/null
$COMPOSE --profile isolation-test up -d --wait isolation-target isolation-attacker >/dev/null
if [ $? -ne 0 ]; then
  echo "FAIL: could not start isolation-test fixtures"
  exit 1
fi

exec_in_attacker() {
  $COMPOSE exec -T isolation-attacker "$@"
}

check_internal_reachable() {
  echo "-- checking attacker -> internal target reachability (expect OK) --"
  if exec_in_attacker sh -c "curl -s -m 5 -o /dev/null -w '%{http_code}' http://isolation-target/ | grep -q 200"; then
    echo "PASS: attacker can reach isolation-target over target_net"
  else
    echo "FAIL: attacker cannot reach isolation-target over target_net (expected reachability)"
    FAIL=1
  fi
}

check_external_blocked() {
  local desc="$1"; shift
  echo "-- checking attacker -> external ($desc) (expect BLOCKED) --"
  if exec_in_attacker sh -c "$*" ; then
    echo "FAIL: attacker reached external target ($desc) — ISOLATION BROKEN"
    FAIL=1
  else
    echo "PASS: attacker blocked from external target ($desc)"
  fi
}

check_internal_reachable
check_external_blocked "raw IP 8.8.8.8:443"        "curl -s -m 5 -o /dev/null https://8.8.8.8/ --connect-timeout 4"
check_external_blocked "raw IP 1.1.1.1:443"        "curl -s -m 5 -o /dev/null https://1.1.1.1/ --connect-timeout 4"
check_external_blocked "DNS resolution of a public host" "nslookup example.com"
check_external_blocked "ICMP ping to 8.8.8.8"      "ping -c 1 -W 3 8.8.8.8"

# NOTE: deliberately NOT `compose down` here -- `down` tears down the whole
# project (all services, regardless of --profile), which would kill any
# already-running SENTINEL LAB stack. `rm -sf` removes only these two
# fixture containers and leaves everything else (and the shared networks)
# untouched.
$COMPOSE rm -sf isolation-target isolation-attacker >/dev/null 2>&1

if [ "$FAIL" -eq 0 ]; then
  echo "=================================================="
  echo "ISOLATION VERIFIED: attacker containers have NO route to any host outside the compose network."
  echo "=================================================="
  exit 0
else
  echo "=================================================="
  echo "ISOLATION FAILURE: one or more checks indicate external reachability. DO NOT proceed."
  echo "=================================================="
  exit 1
fi
