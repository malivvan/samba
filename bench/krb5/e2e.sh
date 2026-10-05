#!/bin/bash
# Kerberos sec=krb5 end-to-end test.
#
# Drives: build -> run the server with a keytab and auth = "kerberos" -> kinit
# -> cifs mount -o sec=krb5 -> md5-verified write/read -> teardown. Run on the
# SMB server host, with a reachable KDC.
#
# Prereqs on the KDC, once (MIT krb5):
#   kadmin.local -q "addprinc -randkey cifs/$(hostname -f)@REALM"
#   kadmin.local -q "ktadd -k /tmp/samba.keytab cifs/$(hostname -f)@REALM"
#   kadmin.local -q "addprinc -pw $USER_PW alice@REALM"
#   scp /tmp/samba.keytab <server>:/etc/samba.keytab
#
# Env overrides: REALM, SPN_HOST, SHARE_DIR, KEYTAB, USER_PRINC, USER_PW, MNT, PORT.
set -euo pipefail

REALM=${REALM:-EXAMPLE.COM}
SPN_HOST=${SPN_HOST:-$(hostname -f)}
SHARE_DIR=${SHARE_DIR:-/srv/krbshare}
KEYTAB=${KEYTAB:-/etc/samba.keytab}
USER=${USER_PRINC:-alice}
USER_PW=${USER_PW:-testpw}
MNT=${MNT:-/mnt/krbtest}
PORT=${PORT:-445}
CFG=$(mktemp /tmp/samba-krb.XXXX.toml)
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v kinit >/dev/null || fail "krb5-workstation (kinit) not installed"
[ -f "$KEYTAB" ] || fail "keytab $KEYTAB missing — create it on the KDC (see header)"
klist -k "$KEYTAB" | grep -q "cifs/$SPN_HOST@$REALM" || fail "keytab lacks cifs/$SPN_HOST@$REALM"

echo "== build =="
go build -o samba ./cmd

mkdir -p "$SHARE_DIR" "$MNT"
cat > "$CFG" <<INI
listen = "0.0.0.0:$PORT"
auth = "kerberos"
log_level = 1
[kerberos]
keytab = "$KEYTAB"
spn = "cifs/$SPN_HOST"
[[share]]
name = "data"
path = "$SHARE_DIR"
INI

echo "== start server =="
./samba --config "$CFG" &
SRV=$!
trap 'kill $SRV 2>/dev/null; umount "$MNT" 2>/dev/null; rm -f "$CFG"' EXIT
sleep 1

echo "== kinit $USER@$REALM =="
echo "$USER_PW" | kinit "$USER@$REALM"

echo "== mount -o sec=krb5 =="
mount -t cifs "//$SPN_HOST/data" "$MNT" -o sec=krb5,vers=3.1.1,cruid="$(id -u)"
klist | grep -q "cifs/$SPN_HOST" && echo "  service ticket acquired"

echo "== md5-verified write/read =="
dd if=/dev/urandom of=/tmp/krb-src bs=1M count=64 status=none
cp /tmp/krb-src "$MNT/krb-file"
sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
A=$(md5sum < /tmp/krb-src | cut -d' ' -f1)
B=$(md5sum < "$MNT/krb-file" | cut -d' ' -f1)
[ "$A" = "$B" ] || fail "md5 mismatch ($A != $B)"
echo "  md5 OK ($A)"

echo "== with signing enforced and sealing on =="
umount "$MNT"
cat > "$CFG" <<INI
listen = "0.0.0.0:$PORT"
auth = "kerberos"
require_signing = true
encrypt = true
log_level = 1
[kerberos]
keytab = "$KEYTAB"
spn = "cifs/$SPN_HOST"
[[share]]
name = "data"
path = "$SHARE_DIR"
INI
kill $SRV 2>/dev/null; sleep 0.5
./samba --config "$CFG" &
SRV=$!
sleep 1
mount -t cifs "//$SPN_HOST/data" "$MNT" -o sec=krb5,vers=3.1.1,seal,cruid="$(id -u)"
dd if=/dev/urandom of=/tmp/krb-src2 bs=1M count=32 status=none
cp /tmp/krb-src2 "$MNT/krb-sealed"
sync
A=$(md5sum < /tmp/krb-src2 | cut -d' ' -f1)
B=$(md5sum < "$MNT/krb-sealed" | cut -d' ' -f1)
[ "$A" = "$B" ] || fail "sealed md5 mismatch ($A != $B)"
echo "  sealed md5 OK ($A)"

echo "PASS: sec=krb5 mount + I/O verified against realm $REALM"
