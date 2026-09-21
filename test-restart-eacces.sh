#!/usr/bin/env bash
# Integration test: tun2proxy container restart EACCES (tproxy-config issue)
#
# Validates two properties of the tproxy-config resolv.conf direct-write path:
#   1. After a fresh container start, the host-side resolv.conf file keeps mode 0644
#      (old versions chmod'ed it to 0444, which broke every subsequent restart).
#   2. If the host-side file was left at 0444 by an older version (upgrade case),
#      a restart must heal it back to 0644 and come back up healthy.
#
# Usage: IMAGE=<tun2proxy image> [PROXY=<ip:port>] ./test-restart-eacces.sh
set -euo pipefail

IMAGE="${IMAGE:?set IMAGE to the tun2proxy image under test}"
PROXY="${PROXY:-192.0.2.1:1080}"  # dummy proxy target; reachability irrelevant for this test
NAME="t2p-restart-test"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

# Phase 1: fresh create must start (tun2proxy exits on fatal error if setup fails)
docker run -d --name "$NAME" --device /dev/net/tun \
  --cap-drop ALL --cap-add NET_ADMIN \
  "$IMAGE" --proxy "http://$PROXY" --dns virtual --exit-on-fatal-error \
  >/dev/null

# Wait up to 15s for either a healthy run or a crash
sleep 5
STATE1=$(docker inspect "$NAME" --format '{{.State.Status}} {{.State.ExitCode}}' 2>/dev/null || echo "gone")
echo "after create: $STATE1"
[ "$STATE1" = "running 0" ] || [ "${STATE1%% *}" = "running" ] || fail "fresh container not running: $STATE1"

# Phase 2: host-side resolv.conf mode must still be 0644 (not poisoned to 0444)
DOCKER_ROOT=$(docker info --format '{{.DockerRootDir}}')
CID=$(docker inspect "$NAME" --format '{{.Id}}')
HOST_RESOLV="$DOCKER_ROOT/containers/$CID/resolv.conf"
MODE=$(stat -c %a "$HOST_RESOLV")
echo "host resolv.conf mode after first run: $MODE"
[ "$MODE" = "644" ] || fail "resolv.conf poisoned: mode $MODE (expected 644)"

# Phase 3: poison host file to 0444 (upgrade scenario) then restart;
# the EACCES heal path must restore 0644 and the container must come back up
chmod 0444 "$HOST_RESOLV" 2>/dev/null || sudo chmod 0444 "$HOST_RESOLV"
docker restart "$NAME" >/dev/null
sleep 5
STATE2=$(docker inspect "$NAME" --format '{{.State.Status}} {{.State.ExitCode}}' 2>/dev/null || echo "gone")
echo "after restart: $STATE2"
[ "${STATE2%% *}" = "running" ] || fail "restart failed: $STATE2 (EACCES crash loop?)"

MODE2=$(stat -c %a "$HOST_RESOLV")
echo "host resolv.conf mode after restart: $MODE2"
[ "$MODE2" = "644" ] || fail "heal failed: mode $MODE2 (expected 644)"

# Phase 4: double-check no EACCES in logs
if docker logs "$NAME" 2>&1 | grep -q "EACCES"; then
  fail "EACCES present in logs after restart"
fi

pass "create healthy, resolv.conf 0644 preserved, restart heals 0444->0644, no EACCES"