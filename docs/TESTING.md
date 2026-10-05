# Testing

Three layers: protocol/unit tests that run anywhere, socket-level integration
tests that drive a running server, and host suites that a real SMB client
(cifs.ko or Windows) exercises on a machine with root, port 445 and
`cifs-utils`. Throughput numbers live in [BENCHMARKS.md](BENCHMARKS.md); this
document is the method.

## Everything at once

```sh
go build ./...
go vet ./...
gofmt -l .                              # must print nothing
go test ./...                           # unit + protocol + socket tests
go test -race ./...                     # the same, under the race detector
go test -run '^$' -fuzz FuzzProcessFrame -fuzztime 60s .
go test -run '^$' -bench . -benchtime 1s .
```

The race detector matters here: the concurrency is real (one goroutine per
connection direction, a watcher goroutine per connection, a mailbox goroutine
per worker, and shared session/lease state), so `-race` is part of the normal
loop, not an occasional extra.

## What the tests cover

| File | Coverage |
|---|---|
| `wire_test.go` | Reader/Writer round trips, bounds behaviour, UTF-16LE (including surrogate pairs), patching, padding |
| `crypto_test.go` | MD4 (RFC 1320 vectors), NT hash, HMAC-MD5 reference value, HMAC-SHA256, AES-CMAC (RFC 4493 vectors), RC4 (known answer), AES-CCM (RFC 3610 vectors), AES-GCM (NIST vector), AEAD round trip plus tamper/wrong-key/wrong-AAD rejection, cipher parameters, the SP800-108 layout, SMB 3.1.1 key derivation |
| `ntlm_test.go` | Token classification (raw and SPNEGO-wrapped), CHALLENGE shape, a full NTLMv2 challenge/response round trip, wrong password and tampered challenge rejection, the RC4 key-exchange path |
| `spnego_test.go` | DER length forms, the mechanism hint (Kerberos before NTLM), classification of SPNEGO-wrapped and raw Kerberos tokens, raw NTLMSSP, NegTokenResp round trip, malformed-blob robustness |
| `config_test.go` | Defaults, unknown-key rejection, every validation rule, the user database (password and `nt_hash`), guest defaults, and a guard that the shipped `samba.toml.example` loads |
| `vfs_test.go` | Traversal/NUL rejection, handle-table generation safety, FILETIME conversion and `UTIME_OMIT` sentinels, directory snapshot patterns and hidden-attribute handling, errno → NTSTATUS mapping |
| `lease_test.go` | Mailbox post/drain and wake semantics, lease grant/refresh, break-only-conflicting-keys, unleased writers break everything, connection teardown releases its grants |
| `netinfo_test.go` | `NETWORK_INTERFACE_INFO` encoding (152 bytes per interface, `Next` chain, link speed, IPv4/IPv6 family), interface enumeration |
| `handlers_test.go` | `RqLs` lease-context parsing (v1, v2, non-lease, truncated, no-progress `Next`), OPLOCK_BREAK frame shape, CHANGE_NOTIFY completion framing and its degrade-to-re-enumerate behaviour |
| `smb2_test.go` | The protocol end to end through `ProcessFrame`: a full session (negotiate → session setup → tree connect → create → write → read → query directory → close), traversal rejection, the zero-copy read plan, NTLMv2 authentication with signing enforcement and response-signature verification, SMB 3.1.1 preauth chaining with an independently recomputed signing key, transform round trip plus tamper, response batching, SMB1 wildcard, undecryptable-frame disconnect, credit clamping |
| `server_test.go` | The same things over a real socket: framing, batched pipelining, the zero-copy read path at several offsets (in a deliberately non-sequential order), IOCTL FSCTLs, a CHANGE_NOTIFY that completes from a real inotify event, **a lease break delivered to the other client**, and rejection of a desynchronized stream |

## Fuzzing

Four native Go fuzz targets cover every parser that touches attacker-controlled
bytes before authentication:

```sh
go test -run '^$' -fuzz FuzzProcessFrame    -fuzztime 60s .
go test -run '^$' -fuzz FuzzNTLM           -fuzztime 60s .
go test -run '^$' -fuzz FuzzClassifyBlob   -fuzztime 60s .
go test -run '^$' -fuzz FuzzParseLeaseCtx  -fuzztime 60s .
```

| Target | Surface |
|---|---|
| `FuzzProcessFrame` | The SMB2 wire entry point: header decode, compound dispatch, and every command's body/offset/length parsing, against a read-only temp share with fresh protocol state per input. It also checks an invariant on the output: every framed response must be complete and well formed, and a zero-copy plan must be bounded. |
| `FuzzNTLM` | NTLMSSP token location, classification, the AUTHENTICATE field decoder, and verification on whatever came out. |
| `FuzzClassifyBlob` | The SPNEGO/GSS DER classifier, including the invariant that a recognized token is a slice of the input rather than synthesized bytes. |
| `FuzzParseLeaseCtx` | The `SMB2_CREATE_CONTEXT` walker, which must always terminate. |

Crashers are written to `testdata/fuzz/<Target>/`; they become permanent
regression cases. CI runs a short smoke on every push and a longer run weekly.

## The host suites (`bench/`)

These need a real client; they are the only way to validate against cifs.ko and
Windows.

| Script | What it does |
|---|---|
| `bench/bench.sh` | Full local suite: start the server on a scratch config, cifs-mount it, run sequential read, sequential write, parallel read, small-file metadata and integrity checks, print a block for BENCHMARKS.md, clean up. Also the place to measure a Samba baseline for comparison. |
| `bench/loopback-multichannel.sh` | Guest and authenticated multichannel on loopback with integrity verification. |
| `bench/cross-vm-read.sh` | Mount over a real NIC, drop the client cache, run parallel readers on distinct files so the traffic is genuinely on the wire. |
| `bench/cross-vm-read-cachenone.sh` | The same with `cache=none`, kept as a cautionary example: it disables readahead and makes any server look bad. |
| `bench/net-iperf.sh` | Raw TCP ceiling between two hosts. Run this before optimizing anything. |
| `bench/win-interop.ps1` | Windows client: `net use`, list, read, write, and `Get-SmbConnection` to confirm dialect and signing. |
| `bench/win-read.ps1` | Windows `.NET FileStream` streamed read throughput. |
| `bench/win-multistream.ps1` | Windows concurrent multi-stream read and write. |
| `bench/krb5/e2e.sh` | `sec=krb5` end to end against a live KDC (see [KERBEROS.md](KERBEROS.md)). |
| `bench/stress/` | Concurrent-mount stress and a long soak, with a CSV artifact and an analyzer for leak verdicts. |

## Test log — what each round found

**Concurrent-mount soak (reference implementation).** A long soak with ~100
concurrent cifs mounts per round across ~100 000 mount/teardown cycles found
zero data faults and a flat RSS baseline (a least-squares slope of +0.005 kB per
round, all of it in the first few hundred rounds), which is what cleared the
lease-table and connection-slot paths of leaks. The same harness is here for
this port to be put through.

**Zero-copy reads and the file offset.** Measured with
`BenchmarkServerReadZeroCopy` at a longer benchtime, this port originally failed
with `unexpected EOF` after a hundred-odd iterations: the naive "copy the file
to the socket" call advances a file descriptor's own position, so a stream of
offset-addressed reads eventually walked past the end of the file. The
sequential test in `server_test.go` had passed by accident, because a sequential
walk is exactly the case where the drift hides. The fix is in `zerocopy.go`
(splice with an explicit offset), and the test now reads at deliberately
non-sequential offsets, including the same offset twice. The lesson is recorded
here because it is the kind of bug a benchmark catches and a happy-path test
does not.

**A batched-response loss.** In the reference implementation an
encrypted (sealed) frame re-encrypted its response into the connection buffer
*after clearing it*, which could discard responses already batched from earlier
frames in the same wakeup. This port appends instead — see
[PORTING.md](PORTING.md) for the list of deliberate divergences.

**Desktop interop findings worth keeping.** Two client behaviours that are easy
to get wrong and are covered by tests here: `.NET FileStream` queries
`FileStreamInformation` and the security descriptor on open, and treats a
`NOT_SUPPORTED` reply as a hard failure (both are implemented); and a
`cache=none` mount disables client readahead, which makes any server's read
throughput look broken (documented in BENCHMARKS.md and TUNING.md).
