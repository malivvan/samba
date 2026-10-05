#!/bin/bash
# Concurrent-mount stress test: launch N containers that each mount the share
# and do verified I/O against a running samba. Run on the server host (clients
# use --network=host → SRV=127.0.0.1) or point SRV at a remote server.
#
#   run-stress.sh [N] [SRV] [SHARE_PATH]
#     N           number of client containers (default 100)
#     SRV         server address reachable from the containers (default 127.0.0.1)
#     SHARE_PATH  share directory on the server host (default /srv/stress)
#
# The server must already be running with a share named "data" pointing at
# SHARE_PATH and a user in its config. Env: SMBUSER, SMBPASS, ITERS, SZ, RUNTIME.
#
# Design notes:
#  - a GO-file start barrier holds all N mounts at once (without it, serial
#    container launch outpaces the quick per-client I/O and only a few
#    connections overlap),
#  - launch failures are counted separately from I/O failures, so a host or
#    podman flake is never misread as a server/data fault.
set -u
N=${1:-100}
SRV=${2:-127.0.0.1}
SHARE_PATH=${3:-/srv/stress}
IMAGE=${IMAGE:-localhost/samba-stress:latest}
SMBUSER=${SMBUSER:-alice}
SMBPASS=${SMBPASS:-testpw123}
CONTAINER=${CONTAINER:-podman}
: "${SHARE_PATH:?}"

mkdir -p "$SHARE_PATH"
dd if=/dev/urandom of="$SHARE_PATH/shared.bin" bs=1M count=8 status=none
rm -f "$SHARE_PATH/GO" "$SHARE_PATH"/u-*.bin

echo "== build client image =="
$CONTAINER build -t "$IMAGE" -f "$(dirname "$0")/Containerfile" "$(dirname "$0")" >/dev/null

echo "== launch $N clients against $SRV =="
for i in $(seq 1 "$N"); do $CONTAINER rm -f "smb-$i" >/dev/null 2>&1; done
launch_fail=0
for i in $(seq 1 "$N"); do
    if ! $CONTAINER run -d --name "smb-$i" --privileged --network=host \
        -e SRV="$SRV" -e SMBUSER="$SMBUSER" -e SMBPASS="$SMBPASS" -e ID="$i" \
        -e ITERS="${ITERS:-3}" -e SZ="${SZ:-8}" "$IMAGE" >/dev/null 2>&1; then
        # A container that never starts is a host/podman launch failure, NOT an
        # I/O-verify failure.
        if ! $CONTAINER run -d --name "smb-$i" --privileged --network=host \
            -e SRV="$SRV" -e SMBUSER="$SMBUSER" -e SMBPASS="$SMBPASS" -e ID="$i" \
            -e ITERS="${ITERS:-3}" -e SZ="${SZ:-8}" "$IMAGE" >/dev/null 2>&1; then
            launch_fail=$((launch_fail + 1))
            echo "  LAUNCH_FAIL container $i (podman run failed twice)"
        fi
    fi
done

echo "== wait for mounts to settle =="
sleep "${SETTLE:-6}"
peak=$(ss -tn state established "( sport = :445 )" 2>/dev/null | grep -c ':445' || true)
rss=$(pgrep -x samba | while read -r p; do awk '/VmRSS/{print $2}' "/proc/$p/status"; done | sort -n | tail -1)
echo "  established :445 connections: ${peak:-?}  server RSS: ${rss:-?} kB"

echo "== release barrier =="
touch "$SHARE_PATH/GO"

echo "== wait for clients =="
pass=0; fail=0
for i in $(seq 1 "$N"); do
    if ! $CONTAINER inspect "smb-$i" >/dev/null 2>&1; then
        continue # launch failure, already counted
    fi
    code=$($CONTAINER wait "smb-$i" 2>/dev/null || echo 3)
    if [ "$code" = "0" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        echo "  FAIL container $i exit=$code: $($CONTAINER logs "smb-$i" 2>&1 | tail -1)"
    fi
done

alive=$(pgrep -x samba | wc -l)
peak2=$(ss -tn state established "( sport = :445 )" 2>/dev/null | grep -c ':445' || true)
rm -f "$SHARE_PATH/GO"
for i in $(seq 1 "$N"); do $CONTAINER rm -f "smb-$i" >/dev/null 2>&1; done

echo "== result =="
echo "  pass=$pass fail=$fail launch_fail=$launch_fail server_processes=$alive"
[ "$launch_fail" -gt 0 ] && echo "==> $launch_fail container(s) failed to launch (host/podman, not server)"
if [ "$fail" -gt 0 ]; then
    echo "==> I/O VERIFY FAILURES — investigate"
    exit 1
fi
if [ "$alive" -eq 0 ]; then
    echo "==> SERVER DIED during the run"
    exit 2
fi
echo "==> OK: $pass/$N clients completed verified I/O, server alive, peak conns ${peak2:-?}"
