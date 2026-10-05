# Testing

Three layers: protocol/unit tests that run anywhere, socket-level integration
tests that drive a running server, and host suites that a real SMB client
(cifs.ko or Windows) exercises on a machine with root, port 445 and
`cifs-utils`. Throughput numbers live in [BENCHMARKS.md](BENCHMARKS.md); this
document is the method.

## Everything at once

```sh
go build ./...                          # the package and cmd
go vet ./...
gofmt -l .                              # must print nothing
go test ./...                           # unit + protocol + socket tests
go test -race ./...                     # the same, under the race detector
go test -run '^$' -fuzz FuzzProcessFrame -fuzztime 60s .
go test -run '^$' -bench . -benchtime 1s .
```

The CLI is the cheapest gate for anything a client can see: it reports what a
configuration will advertise without binding anything, so it is worth running
before the full suite.

```sh
# what will this configuration actually serve?
go run ./cmd --check --config /etc/samba/samba.toml
# the resolved configuration, with every credential redacted
go run ./cmd --dump-config --config /etc/samba/samba.toml
# the negotiation facts
go run ./cmd --list-dialects
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
| `spnego_test.go` | DER length forms, the mechanism hint (NTLMSSP only — Kerberos must never be advertised), classification of SPNEGO-wrapped and raw tokens including a Kerberos AP-REQ, raw NTLMSSP, NegTokenResp round trip, malformed-blob robustness |
| `config_test.go` | Defaults, unknown-key rejection, every validation rule, the user database (password and `nt_hash`), guest defaults, and a guard that the shipped `samba.toml.example` loads |
| `vfs_test.go` | Traversal/NUL rejection, handle-table generation safety, FILETIME conversion and `UTIME_OMIT` sentinels, directory snapshot patterns and hidden-attribute handling, errno → NTSTATUS mapping |
| `lease_test.go` | Mailbox post/drain and wake semantics, lease grant/refresh, break-only-conflicting-keys, unleased writers break everything, connection teardown releases its grants |
| `netinfo_test.go` | `NETWORK_INTERFACE_INFO` encoding (152 bytes per interface, `Next` chain, link speed, IPv4/IPv6 family), interface enumeration |
| `handlers_test.go` | `RqLs` lease-context parsing (v1, v2, non-lease, truncated, no-progress `Next`), OPLOCK_BREAK frame shape, CHANGE_NOTIFY completion framing and its degrade-to-re-enumerate behaviour |
| `smb2_test.go` | The protocol end to end through `ProcessFrame`: a full session (negotiate → session setup → tree connect → create → write → read → query directory → close), traversal rejection, the zero-copy read plan, NTLMv2 authentication with signing enforcement and response-signature verification, SMB 3.1.1 preauth chaining with an independently recomputed signing key, transform round trip plus tamper, response batching, SMB1 wildcard, undecryptable-frame disconnect, credit clamping |
| `commands_test.go` | Every SMB2 command on a real session: NEGOTIATE variants and cipher choice, the session-setup policy and multichannel binding, TREE_CONNECT/DISCONNECT (including the `IPC$` stub), every CREATE disposition and its errors, READ/WRITE/FLUSH/CLOSE, every QUERY_INFO and SET_INFO class, all six QUERY_DIRECTORY classes plus continuation and restart, LOCK (shared, exclusive, unlock, conflicts, batch unwind), IOCTL, CHANGE_NOTIFY, LOGOFF, compounds, and lease grants |
| `malformed_test.go` | Every request truncated at every length: the server must answer with a protocol error, never panic, never accept garbage and never drop the connection — the error branch of every body decoder in one sweep |
| `auth_test.go` | The session-setup branches: SPNEGO wrapping, re-authentication, guest and anonymous decisions, encryption-required refusals, the refusal of a Kerberos token, and the full multichannel channel-binding handshake (accepted, rejected, and guest) |
| `limits_test.go`, `caps_test.go` | The resource limits and the budget's blocking/shutdown semantics, and the protocol-level refusal of each cap |
| `hardening_test.go` | The transport's hardening: the connection cap, incomplete-frame reaping, the zero-copy stall deadline and its correctness, break routing, deferred-frame writing, panic containment, and clean shutdown |
| `edge_test.go` | The remaining edges: AEAD and CMAC error paths, the CCM length-prefix forms, `clamp`/`isHex`, handle-table misses, the response write stall, and path/metadata variants |
| `server_test.go` | The same things over a real socket: framing, batched pipelining, the zero-copy read path at several offsets (in a deliberately non-sequential order), IOCTL FSCTLs, a CHANGE_NOTIFY that completes from a real inotify event, **a lease break delivered to the other client**, and rejection of a desynchronized stream |
| `introspect_test.go` | The introspection contract: the published dialect and cipher lists against the negotiation code that consumes them (names, revision codes, key sizes, preference order), the capability report against a configuration, and the live counters against a real connection |
| `version_test.go` | `Version` against the newest released `CHANGELOG.md` heading — the drift the release job refuses to publish |
| `cmd/main_test.go`, `cmd/cli_test.go` | The CLI: exit statuses, `--help` completeness, the `--list-*` reports, that `--dump-config` never prints a credential, that the overrides beat the file, and that the report carries every capability the library publishes with the right state |

## Coverage

```sh
go test -coverprofile=/tmp/cov.out ./... && go tool cover -func=/tmp/cov.out | tail -1
```

Statement coverage is **94%** across the module (and 89% for the CLI). The
remaining lines are error branches that cannot be reached on a working system
(an unreadable `/sys/class/net/*/speed`, a filesystem reporting a zero fragment
size, `crypto/rand` failing, a `poll(2)` error other than `EINTR`), or defensive
paths whose trigger would be a bug elsewhere. Coverage was raised by writing
tests for behaviour a client depends on — statuses, byte layouts, error
classification — not by chasing lines.

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
| `FuzzClassifyBlob` | The SPNEGO DER classifier, including the invariant that a recognized token is a slice of the input rather than synthesized bytes. |
| `FuzzParseLeaseCtx` | The `SMB2_CREATE_CONTEXT` walker, which must always terminate. |

Crashers are written to `testdata/fuzz/<Target>/`; they become permanent
regression cases. CI runs a short smoke on every push and a longer run weekly.

## CI

Everything lives in one workflow, `.github/workflows/ci.yml`, which runs on
every push, on pull requests, and weekly (Sunday 03:00 UTC, for the long fuzz
run):

| Job | What it does | Gates the release |
|---|---|---|
| `test` | `gofmt`, `go vet`, a `CGO_ENABLED=0` build, `go test ./...` and `go test -race ./...` on Ubuntu, macOS and Windows | yes (Linux leg) |
| `lint` | `golangci-lint` with `.golangci.yml`, plus the guard that no shipping file imports `C` or `unsafe` | yes |
| `coverage` | `go test -covermode=atomic -coverprofile`, the total printed, the profile uploaded as an artifact, and the result sent to Coveralls | yes |
| `fuzz` | Every target in the table above, 60s each on a push and 15 minutes each weekly; crashers are uploaded as artifacts | yes |
| `interop` | `bench/interop-smbclient.sh` against the built binary | no |
| `cross-build` | `GOOS=linux GOARCH=arm64 go build ./...` | no |
| `release` | Only on a `v*` tag: builds both static binaries, smoke-tests `--version` and `--check`, runs the benchmarks, and creates the GitHub release with the results in its description | — |

Two things about that are deliberate and easy to mistake for mistakes:

- **The macOS and Windows legs are `continue-on-error`.** The server is
  Linux-only by design (`docs/PORTING.md`), so those legs cannot build yet. They
  run so the drift is visible the day it changes, but only the Linux leg is a
  gate — a red Windows leg never blocks lint, coverage or a release.
- **`release` is gated by `needs`,** so it is skipped, not failed, when any of
  `lint`, `coverage`, `test` or `fuzz` does not pass. It also refuses to publish
  a tag that disagrees with `Version` in `doc.go`; `TestVersionMatchesChangelog`
  catches the same drift before a tag exists.

## The host suites (`bench/`)

These need a real client; they are the only way to validate against cifs.ko and
Windows.

| Script | What it does |
|---|---|
| `bench/interop-smbclient.sh` | Drives a running server with Samba's `smbclient` (no root needed): the dialect matrix from SMB 2.0.2 to 3.1.1, md5-verified 20 MiB round trips, mkdir/rename/delete, NTLMv2 with signing enforced, wrong-password rejection, and SMB3 encryption. |
| `bench/bench.sh` | Full local suite: start the server on a scratch config, cifs-mount it, run sequential read, sequential write, parallel read, small-file metadata and integrity checks, print a block for BENCHMARKS.md, clean up. Also the place to measure a Samba baseline for comparison. |
| `bench/loopback-multichannel.sh` | Guest and authenticated multichannel on loopback with integrity verification. |
| `bench/cross-vm-read.sh` | Mount over a real NIC, drop the client cache, run parallel readers on distinct files so the traffic is genuinely on the wire. |
| `bench/cross-vm-read-cachenone.sh` | The same with `cache=none`, kept as a cautionary example: it disables readahead and makes any server look bad. |
| `bench/net-iperf.sh` | Raw TCP ceiling between two hosts. Run this before optimizing anything. |
| `bench/win-interop.ps1` | Windows client: `net use`, list, read, write, and `Get-SmbConnection` to confirm dialect and signing. |
| `bench/win-read.ps1` | Windows `.NET FileStream` streamed read throughput. |
| `bench/win-multistream.ps1` | Windows concurrent multi-stream read and write. |
| `bench/stress/` | Concurrent-mount stress and a long soak, with a CSV artifact and an analyzer for leak verdicts. |

## Interop with a real client

`bench/interop-smbclient.sh` runs Samba's client against the server and checks
the outcome rather than the log, so it is a genuine interop gate. On the
development host it passes 13/13: every dialect from SMB 2.0.2 through 3.1.1
(negotiating 3.1.1 with AES-128-GCM when offered), a 20 MiB upload+download
verified by md5, small-file transfers, mkdir/rename/delete with the share left
clean, NTLMv2 authentication with `require_signing = true`, a wrong password
rejected with `NT_STATUS_LOGON_FAILURE`, and — with `encrypt = true` on the
server — a sealed 20 MiB round trip through AES-128-GCM.

That suite is the reason several bugs are not in this port. Driving the protocol
from unit tests alone had hidden them:

- **Pipelined reads were dropped.** When a batch of frames contained a read that
  qualified for the zero-copy path, the frames after it were discarded instead
  of being held for the next turn. `smbclient` — which keeps several reads in
  flight — reported `parallel_read returned NT_STATUS_IO_TIMEOUT`.
  `TestServerPipelinedZeroCopyReads` and `TestServerPipelinedMixedBatch` now
  pipeline reads (and mixed reads and echoes) into one write and require a
  response to every one; reverting the fix makes them fail with the same timeout
  the real client saw.
- **Encryption was advisory, not enforced.** A session told to seal would still
  be served a plaintext request. It is now refused, and a sealed request on the
  same session is served and answered with a sealed response — asserted end to
  end with independently derived keys in
  `TestEncryptRequiredRejectsPlaintextAndServesSealed`.
- **Samba's client could not enable encryption at all.** Its NTLMSSP client
  requires the server to echo `NEGOTIATE_SEAL` before it will turn sealing on;
  the challenge now echoes it when asked.
- **Wildcard directory searches returned nothing.** The search pattern a client
  sends with QUERY_DIRECTORY was compared for equality, so `ls f1*.txt` and
  `del *` answered `NT_STATUS_NO_SUCH_FILE`. Patterns are now matched as DOS
  wildcards (`pattern.go`, with a table-driven unit test), and the interop suite
  lists by wildcard and checks that an unmatched pattern still reports no such
  file.

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
