#!/usr/bin/env bash
# Guest and authenticated multichannel on loopback, with integrity verification.
# Usage: loopback-multichannel.sh [binary] [share-dir] [config-dir]
# Requires: root, cifs-utils, a free port 445, and a 1 GiB $SHARE/data/big.bin.
set -u
BIN=${1:-./samba}
SHARE=${2:-/srv/samba-test}
CFGDIR=${3:-.}
MNT=/mnt/samba-mc

for m in $MNT; do umount -l "$m" 2>/dev/null; done
pkill -9 -x samba 2>/dev/null; sleep 1
echo "stale procs: $(pgrep -x samba | wc -l)"

agg() { # label cfg mountopts
    local label="$1" cfg="$2" opts="$3"
    pkill -9 -x samba 2>/dev/null; sleep 1
    nohup "$BIN" --config "$cfg" > /tmp/samba-mc.log 2>&1 &
    sleep 1.5
    cat "$SHARE/big.bin" >/dev/null
    mount -t cifs //127.0.0.1/data "$MNT" -o "$opts" || { echo "$label: MOUNT FAIL"; return; }
    local S=$(date +%s.%N)
    for i in 1 2 3 4; do dd if="$MNT/big.bin" of=/dev/null bs=1M 2>/dev/null & done; wait
    local E=$(date +%s.%N)
    local bound=$(grep -c "channel bound" /tmp/samba-mc.log)
    echo "$S $E $label $bound" | awk '{printf "%s: %.1f GB/s (%.0f Gbps), channels bound=%s\n", $3, 4/($2-$1), 4*8/($2-$1), $4}'
    cmp -s "$SHARE/big.bin" "$MNT/big.bin" && echo "   integrity OK" || echo "   INTEGRITY FAIL"
    umount -l "$MNT" 2>/dev/null
}
# Configs are expected to be prepared by the caller; the shapes are:
#   mc.toml       guest, multichannel = true
#   mc-auth.toml  multichannel = true plus a [[user]]
agg "guest-mc-zerocopy" "$CFGDIR/mc.toml"      "guest,vers=3.1.1,multichannel,max_channels=4"
agg "auth-mc-signed"    "$CFGDIR/mc-auth.toml" "username=alice,password=testpw,vers=3.1.1,multichannel,max_channels=4"
pkill -9 -x samba 2>/dev/null
