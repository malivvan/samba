#!/bin/bash
# Long soak: run the concurrent-mount stress round ROUNDS times, recording
# per-round stats for a leak verdict.
#
#   soak.sh [ROUNDS] [N] [SRV] [SHARE_PATH]
#
# Writes CSV `round,epoch_s,pass,fail,launch_fail,rss_kb,peak_conns,duration_s`
# to $STATS_CSV (default /tmp/soak-stats.csv), aborts if the server dies, and
# runs analyze-soak.sh on the CSV at the end.
set -u
ROUNDS=${1:-1000}
N=${2:-100}
SRV=${3:-127.0.0.1}
SHARE_PATH=${4:-/srv/stress}
STATS_CSV=${STATS_CSV:-/tmp/soak-stats.csv}
HERE=$(dirname "$0")

echo "round,epoch_s,pass,fail,launch_fail,rss_kb,peak_conns,duration_s" > "$STATS_CSV"
start=$(date +%s)
for r in $(seq 1 "$ROUNDS"); do
    t0=$(date +%s)
    out=$("$HERE/run-stress.sh" "$N" "$SRV" "$SHARE_PATH" 2>&1)
    rc=$?
    t1=$(date +%s)
    pass=$(echo "$out" | sed -n 's/.*pass=\([0-9]*\).*/\1/p' | tail -1)
    fail=$(echo "$out" | sed -n 's/.*fail=\([0-9]*\) launch_fail.*/\1/p' | tail -1)
    lf=$(echo "$out" | sed -n 's/.*launch_fail=\([0-9]*\).*/\1/p' | tail -1)
    rss=$(pgrep -x samba | while read -r p; do awk '/VmRSS/{print $2}' "/proc/$p/status"; done | sort -n | tail -1)
    conns=$(ss -tn state established "( sport = :445 )" 2>/dev/null | grep -c ':445' || true)
    echo "$r,$(date +%s),${pass:-0},${fail:-0},${lf:-0},${rss:-0},${conns:-0},$((t1 - t0))" >> "$STATS_CSV"
    printf "round %d/%d pass=%s fail=%s rss=%s kB conns=%s (%ds)\n" \
        "$r" "$ROUNDS" "${pass:-?}" "${fail:-?}" "${rss:-?}" "${conns:-?}" "$((t1 - t0))"

    if [ "$rc" = "2" ]; then
        echo "ABORT: the server died in round $r"
        break
    fi
done
total=$(( $(date +%s) - start ))
echo "soak finished in $((total / 60))m; stats: $STATS_CSV"
"$HERE/analyze-soak.sh" "$STATS_CSV"
