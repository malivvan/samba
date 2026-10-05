# Soak results

CSV artifacts from long `soak.sh` runs live here so `analyze-soak.sh` can be
re-run on them at any time:

```sh
bench/stress/soak.sh 1000 100 127.0.0.1 /srv/stress
cp /tmp/soak-stats.csv bench/stress/results/soak-1000-$(date -u +%F).csv
bench/stress/analyze-soak.sh bench/stress/results/soak-1000-$(date -u +%F).csv
```

Record what the run was against (host, kernel, worker count, share filesystem)
in `docs/BENCHMARKS.md` next to the numbers: an RSS slope only means something
when you know what produced it.
