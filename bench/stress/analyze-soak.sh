#!/bin/bash
# Analyze a soak.sh stats CSV
# (round,epoch_s,pass,fail,launch_fail,rss_kb,peak_conns,duration_s).
#
# Reports I/O pass/fail, the RSS trend (least-squares slope plus first/last
# quartile means → plateau vs linear-leak verdict), peak-connection coverage
# and timing. Portable awk; runs on macOS or Linux.
#
#   analyze-soak.sh [stats.csv]   (default /tmp/soak-stats.csv)
set -u
CSV=${1:-/tmp/soak-stats.csv}
[ -f "$CSV" ] || { echo "no stats file: $CSV" >&2; exit 1; }

awk -F, '
NR == 1 { next }
{
    n++
    pass += $3; fail += $4; lf += $5
    x[n] = $1; y[n] = $6
    if ($7 > peak) peak = $7
    if ($8 > dmax) dmax = $8
    dtot += $8
}
END {
    if (n == 0) { print "no rounds recorded"; exit }
    printf "rounds           : %d\n", n
    printf "I/O verified     : %d passed, %d failed, %d launch failures\n", pass, fail, lf
    printf "peak connections : %d\n", peak
    printf "round duration   : mean %.1fs, max %ds\n", dtot / n, dmax
    printf "RSS              : first %s kB, last %s kB, min %s kB, max %s kB\n", y[1], y[n], ymin, ymax

    # Least-squares slope of RSS against round number.
    sx = sy = sxx = sxy = 0
    for (i = 1; i <= n; i++) { sx += x[i]; sy += y[i] }
    mx = sx / n; my = sy / n
    for (i = 1; i <= n; i++) { dx = x[i] - mx; sxx += dx * dx; sxy += dx * (y[i] - my) }
    slope = (sxx > 0) ? sxy / sxx : 0

    # First vs last quartile mean: a plateau shows up as a small delta.
    q = int(n / 4); if (q < 1) q = 1
    for (i = 1; i <= q; i++) fq += y[i]
    fq /= q
    for (i = n - q + 1; i <= n; i++) lq += y[i]
    lq /= q
    printf "RSS slope        : %+.4f kB/round\n", slope
    printf "RSS quartiles    : first %.0f kB, last %.0f kB (delta %+.0f kB)\n", fq, lq, lq - fq

    verdict = (slope < 0.05 && (lq - fq) < 64) ? "PLATEAU — no leak" : "GROWING — investigate"
    printf "VERDICT          : %s\n", verdict
}
' "$CSV"
