# Concurrent-mount stress test

Launches `N` containers that each `mount -t cifs` the share (with `nosharesock`,
so every client gets its own connection) and do verified I/O against a running
server. It shakes out the concurrency the unit tests cannot reach: lease-table
contention, cross-worker break delivery under load, connection-slot churn,
memory scaling, and mount/teardown storms.

## Run (on the server host)

```sh
# 1. the server listening on :445 with a share "data" (path /srv/stress) and a
#    user in its config:
#      listen = "0.0.0.0:445"
#      oplocks = true
#      [[user]]  name = "alice"  password = "testpw123"
#      [[share]] name = "data"   path = "/srv/stress"
go build -o samba ./cmd && sudo ./samba --config /etc/samba/samba.toml &

# 2. fire the fleet (needs podman; root, for privileged cifs mounts)
sudo bench/stress/run-stress.sh 100                 # 100 containers, loopback
sudo bench/stress/run-stress.sh 100 10.99.0.10      # against a remote server
```

Each container (`client.sh`) mounts, waits at a **start barrier** (until the
launcher drops `GO` on the share) so all `N` clients hold their mounts at once,
then writes a unique random file, reads it back and **md5-verifies** it, reads a
shared file each pass (lease grant + break churn), repeats `ITERS` times
(default 3, `SZ` = 8 MiB), and unmounts. Exit 0 means all I/O verified.

`run-stress.sh` builds the image once, launches the containers, waits for the
mounts to settle, releases the barrier, reports `pass`/`fail` and whether the
server is still alive. Set `BARRIER=0` for a staggered (non-simultaneous) run.

Launch failures are counted separately from I/O failures: under heavy container
create rates podman occasionally flakes a `run`, and that must never be reported
as a server or data fault.

## What to watch

- Every container exits 0 (no `VERIFY_FAIL` / `MOUNT_FAIL`), and the server
  stays alive.
- Server RSS stays bounded across runs — no per-connection or lease-table leak.
- No errors in the server log, and teardown leaves no leaked leases or
  connection slots.

## Soak

`soak.sh [ROUNDS] [N] [SRV] [SHARE_PATH]` runs the round `ROUNDS` times
(default 1000), appending per-round stats to `STATS_CSV`
(`round,epoch_s,pass,fail,launch_fail,rss_kb,peak_conns,duration_s`, default
`/tmp/soak-stats.csv`), aborts if the server dies, and finishes by running
`analyze-soak.sh` for a leak verdict: the least-squares RSS slope plus
first/last-quartile means, which separates a plateau from a linear leak.

Keep the CSV from a long run (as `results/`) so the analyzer can be re-run on it
at any time.

### Reference result (reference implementation, its development host)

1000 rounds × ~100 concurrent mounts, ~100 000 mount/teardown cycles, 17.6 h:
99 999 of 100 000 md5-verified I/O operations passed (the single miss was a
podman launch flake), the server stayed alive from start to finish, and RSS went
1700 → 1732 kB with all of the growth in the first ~180 rounds — a slope of
+0.005 kB/round, i.e. a plateau. Verdict: no leak in the connection-slot,
lease-table or cross-worker break paths.

This harness is here so the same run can be made against this port and recorded
in `results/`.
