#!/bin/bash
# Samba-client interop suite: drive a running server with smbclient across the
# dialect matrix, file operations (md5-verified), authentication and SMB3
# encryption. No root is needed (unprivileged port), so this runs anywhere
# smbclient is installed.
#
#   bench/interop-smbclient.sh [binary]
#
# Requires: smbclient (cifs-utils is not enough), coreutils, a free port.
set -u
BIN=${1:-./samba}
PORT=${PORT:-14455}
PORT_AUTH=${PORT_AUTH:-14456}
WORK=$(mktemp -d /tmp/samba-interop-XXXX)
DATA=$WORK/data
PASS=0
FAIL=0

cleanup() {
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "${AUTH_PID:-}" ] && kill "$AUTH_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "FAIL: binary $BIN not found (go build -o samba ./cmd)"; exit 1; }
command -v smbclient >/dev/null || { echo "FAIL: smbclient not installed"; exit 1; }

ok()   { PASS=$((PASS+1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want [$3], got [$2])"; fi; }

mkdir -p "$DATA"
head -c 20000000 /dev/urandom > "$WORK/big.bin"
cp "$WORK/big.bin" "$DATA/big.bin"
echo "hello from the server" > "$DATA/greeting.txt"

cat > "$WORK/guest.toml" <<INI
listen = "127.0.0.1:$PORT"
workers = 2
log_level = 0
[[share]]
name = "data"
path = "$DATA"
INI

cat > "$WORK/auth.toml" <<INI
listen = "127.0.0.1:$PORT_AUTH"
workers = 1
log_level = 0
require_signing = true
encrypt = true
[[share]]
name = "data"
path = "$DATA"
[[user]]
name = "alice"
password = "s3cret"
INI

"$BIN" --config "$WORK/guest.toml" > "$WORK/guest.log" 2>&1 &
SRV_PID=$!
"$BIN" --config "$WORK/auth.toml" > "$WORK/auth.log" 2>&1 &
AUTH_PID=$!
sleep 1

echo "== dialect matrix (guest) =="
for m in SMB2_02 SMB2_10 SMB2_22 SMB3 SMB3_00 SMB3_02 SMB3_11; do
    out=$(smbclient //127.0.0.1/data -N -p "$PORT" -m "$m" -c 'ls greeting.txt' 2>&1)
    if echo "$out" | grep -q greeting.txt; then ok "$m"; else bad "$m: $(echo "$out" | tail -1)"; fi
done

echo "== file operations (guest) =="
smbclient //127.0.0.1/data -N -p "$PORT" -c 'mkdir d; cd d; put '"$WORK"'/big.bin up.bin; ls; get up.bin '"$WORK"'/dl.bin; del up.bin; cd ..; rmdir d' >/dev/null 2>&1
check "20 MiB round trip + mkdir/rmdir/rm/del" \
    "$(md5sum < "$WORK/big.bin" | cut -d' ' -f1)" "$(md5sum < "$WORK/dl.bin" | cut -d' ' -f1)"
smbclient //127.0.0.1/data -N -p "$PORT" -c 'get greeting.txt '"$WORK"'/g.out' >/dev/null 2>&1
check "small file download" "$(cat "$WORK/g.out")" "hello from the server"

# Search patterns are applied by the server, so a wildcard listing must come
# back filtered and a pattern that matches nothing must report no such file.
mkdir -p "$DATA/many"
for i in 1 2 10 20; do echo "x" > "$DATA/many/f$i.txt"; done
echo "x" > "$DATA/many/g1.md"
out=$(smbclient //127.0.0.1/data -N -p "$PORT" -c 'cd many; ls f1*.txt' 2>&1)
check "wildcard listing matches f1*.txt" "$(echo "$out" | grep -cE 'f1\.txt|f10\.txt')" "2"
out=$(smbclient //127.0.0.1/data -N -p "$PORT" -c 'cd many; ls f?.txt' 2>&1)
check "single-character wildcard matches exactly one character" "$(echo "$out" | grep -cE 'f[0-9]\.txt')" "2"
out=$(smbclient //127.0.0.1/data -N -p "$PORT" -c 'cd many; ls nope*.txt' 2>&1)
if echo "$out" | grep -q NT_STATUS_NO_SUCH_FILE; then ok "unmatched pattern reports no such file"; else bad "unmatched pattern: $(echo "$out" | tail -1)"; fi
rm -rf "$DATA/many"

check "no leftovers in the share" "$(find "$DATA" -type f | wc -l)" "2"

echo "== authentication and encryption =="
out=$(smbclient //127.0.0.1/data -U alice%s3cret -p "$PORT_AUTH" -m SMB3_11 -c 'ls greeting.txt' 2>&1)
if echo "$out" | grep -q greeting.txt; then ok "NTLMv2 + require_signing + encrypt"; else bad "authenticated ls: $(echo "$out" | tail -1)"; fi
out=$(smbclient //127.0.0.1/data -U alice%wrong -p "$PORT_AUTH" -m SMB3_11 -c 'ls' 2>&1)
if echo "$out" | grep -q NT_STATUS_LOGON_FAILURE; then ok "wrong password rejected"; else bad "wrong password: $(echo "$out" | tail -1)"; fi
smbclient //127.0.0.1/data -U alice%s3cret -p "$PORT_AUTH" --client-protection=encrypt -m SMB3_11 \
    -c 'get big.bin '"$WORK"'/enc.bin; put '"$WORK"'/big.bin encup.bin; del encup.bin' >/dev/null 2>&1
check "sealed 20 MiB round trip" \
    "$(md5sum < "$WORK/big.bin" | cut -d' ' -f1)" "$(md5sum < "$WORK/enc.bin" | cut -d' ' -f1)"
echo "== done: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ] || exit 1
