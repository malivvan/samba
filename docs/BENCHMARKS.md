# Benchmarks

Two suites measure this server. Record every run below, newest first.
**Any performance-relevant change is re-measured before release.**

## How to measure

**In-repository benchmarks** (run anywhere, including CI):

```sh
go test -run '^$' -bench . -benchtime 1s .            # everything
go test -run '^$' -bench 'BenchmarkServer' -benchtime 1s .   # socket level only
```

The `BenchmarkServer*` entries drive a real SMB2 client against a running server
over TCP on loopback and call `b.SetBytes`, so the reported MB/s is throughput.
The rest are per-message costs: the ECHO round trip through `ProcessFrame`,
signing, the AEAD ciphers, the NT hash, the KDF, and a directory snapshot. Note
that the socket benchmarks include the client, and keep exactly one request in
flight, so they measure a floor: a real client pipelines, and multichannel
spreads one mount across cores.

**End-to-end suite** (`bench/bench.sh`, run as root on a Linux host with
`cifs-utils`):
- Loopback mount: `mount -t cifs //127.0.0.1/bench ... -o guest,vers=3.0`
- A 1 GiB random file, warmed into the server's page cache, so the measurement
  is of the SMB data path and not the disk
- Reads: the client cache is dropped between runs (umount/remount)
- Writes: `dd conv=fsync`, 512 MiB of zeros
- To compare against Samba, point the same script at a Samba instance serving
  the same directory with the same `dd` commands

Because a fair comparison needs both servers on the same host, network and
storage, the suite is the only place a Samba number should be recorded.

## Results

### 2026-10-05 — the Go port, first recorded run

Intel Core i7-8550U (4 cores / 8 threads), Linux 7.0, loopback, one worker.
Headline transfers with `-bench 'Headline' -benchtime 3x`, everything else with
`-benchtime 1s`:

| Benchmark | Throughput | Per op |
|---|---|---|
| `BenchmarkServerHeadlineRead1GiB` (1 GiB in 1 MiB requests) | 846 MB/s | 1.27 s |
| `BenchmarkServerHeadlineWrite512MiB` (512 MiB in 1 MiB requests) | 553 MB/s | 0.97 s |
| `BenchmarkServerReadZeroCopy` (1 MiB reads) | 968 MB/s | 1.08 ms |
| `BenchmarkServerReadBuffered` (4 KiB reads) | 52 MB/s | 78.6 µs |
| `BenchmarkServerWrite` (1 MiB writes) | 707 MB/s | 1.48 ms |
| `BenchmarkServerMetaOps` (create+write+close) | 4 450 ops/s | 245 µs |
| `BenchmarkServerPipelinedEcho` (32 per round trip) | 5.8 MB/s of requests | 399 µs |
| `BenchmarkAEADSealOpenGCM128` (64 KiB seal+open) | 527 MB/s | 124 µs |
| `BenchmarkAEADSealOpenGCM256` | 489 MB/s | 134 µs |
| `BenchmarkAEADSealOpenCCM128` | 60 MB/s | 1.10 ms |
| `BenchmarkAEADSealOpenCCM256` | 51 MB/s | 1.29 ms |
| `BenchmarkSignAESCMAC` (1 MiB message) | 342 MB/s | 3.07 ms |
| `BenchmarkSignHMACSHA256` (1 MiB message) | 274 MB/s | 3.83 ms |
| `BenchmarkVerifySignature` (4 KiB message) | 308 MB/s | 13.3 µs |
| `BenchmarkNTHash` | — | 585 ns |
| `BenchmarkHMACMD5` | — | 1.26 µs |
| `BenchmarkKDF128` | — | 2.29 µs |
| `BenchmarkProcessFrameEcho` | — | 193 ns, 1 alloc |
| `BenchmarkProcessFrameNegotiate` | — | 1.19 µs, 13 allocs |
| `BenchmarkBuildReadRespPrefix` | — | 42 ns, 0 allocs |
| `BenchmarkDirSnapshot` (256 entries) | — | 804 µs |

Observations from this run:

- **These are floors, not ceilings.** The benchmark client keeps exactly one
  request in flight, so the headline numbers are bounded by round-trip latency
  plus the kernel-side transfer, not by the server's capacity. Its per-read
  allocation also dominates the reported `B/op` (about 2 MB per 1 MiB read in
  the client: the frame buffer plus the body copy) — the *server* never
  allocates the payload on the zero-copy path, which is the point of it. A real
  client pipelines, and `processBatch` exists to answer those batches in one
  write.
- **The zero-copy path is worth roughly 18× the buffered path on the same
  hardware** for large reads (968 MB/s vs the 4 KiB path's 52 MB/s, which is
  dominated by one round trip per read). It also allocates 16 objects per 1 MiB
  read — the pipe, the header and the channel traffic — while the file data is
  never in userspace.
- **CCM is ~9× slower than GCM** in this port (60 MB/s vs 527 MB/s for 128-bit
  keys). AES-CCM is implemented here (Go has no CCM in the standard library)
  and its CBC-MAC pass encrypts every block twice — once for the MAC and once
  for the CTR keystream — through the `cipher.Block` interface. GCM uses Go's
  hardware-accelerated implementation. **Prefer GCM** (the default) and treat
  CCM as a compatibility path; the server picks the client's first offered
  cipher unless `prefer_aes256` is set, and both `prefer_aes256` and the
  client's usual order pick GCM first.
- **Signing costs ~3 ms/MiB**, which is why signed sessions take the buffered
  read path: the signature covers the payload, so the payload must be in
  userspace to be hashed or MAC'd. This is the same trade-off the reference
  implementation documented; unsigned guest traffic is the fast path.

### Reference-point measurements (different hardware, for orientation only)

The reference implementation this port is verified against published these
loopback numbers on its development host (8 cores, Fedora, kernel 6.17). They
are **not** a comparison with this port — different CPU, kernel and transport —
and exist only to record what shape the numbers took:

| Test | Reference implementation | Samba (same host) |
|---|---|---|
| 1 GiB sequential read | 5.7–6.2 GB/s | 1.4 GB/s |
| 512 MiB sequential write (fsync) | ~1.0 GB/s | 0.64 GB/s |
| one mount, 4 channels (multichannel), loopback | 21 GB/s | n/a |
| signed 1 GiB read | ~527 MB/s | n/a (unsigned 1.4 GB/s) |
| 4 mounts, one reader each, loopback | 12.5 GB/s | n/a |

To make a real comparison, run `bench/bench.sh` against this server and against
Samba **on the same host** and record both in this file.

## Tuning findings

- **Write throughput is pipelining-bound.** A client issues streams of `wsize`
  WRITEs. Serving them one at a time loses roughly a third of the achievable
  throughput; batching every complete frame per wakeup into one response write
  roughly doubled it in the reference implementation. This port batches the
  same way (up to 64 frames or a 1 MiB response watermark per wakeup) — see
  `processBatch` in `server.go`.
- **A large advertised read size hurts reads.** Advertising `MaxReadSize = 4 MiB`
  made clients ask for 4 MiB reads and collapsed throughput (0.67 GB/s vs
  5.8 GB/s in the reference measurement): fewer, larger requests defeat client
  readahead parallelism. Hence `MaxReadTarget = 1 MiB` while `MaxWriteSize`
  stays 4 MiB (bigger writes mean fewer round trips).
- **The network, not the server, is usually the ceiling.** In the reference
  cross-VM testing a single-queue virtio NIC at MTU 1500 capped ~9 Gbps for both
  iperf and SMB; with multiqueue and jumbo frames raw TCP reached ~80 Gbps and
  SMB ~47 Gbps over 8 readers. Check the link before optimizing the server.
- **`cache=none` cripples read benchmarks.** It disables client readahead, so
  reads go synchronous and channels cannot fill. Drop the client's page cache
  instead (`echo 3 > /proc/sys/vm/drop_caches`) and read distinct files.

## Known gaps

- Only one request in flight per connection (see
  [CONCURRENCY.md](CONCURRENCY.md)).
- Small-file metadata throughput has not been compared against Samba yet; the
  suite measures it.
- Encrypted reads take the buffered path, so their throughput is bounded by the
  cipher (see the AEAD numbers above) plus the signing/hashing cost.
