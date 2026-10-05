# samba

[![CI](https://github.com/malivvan/samba/actions/workflows/ci.yml/badge.svg)](https://github.com/malivvan/samba/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/malivvan/samba.svg)](https://pkg.go.dev/github.com/malivvan/samba)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A from-scratch SMB2/SMB3 file server (an `smbd` replacement) written in **pure
Go** — no CGO, no `unsafe`, anywhere in the module. It speaks SMB 2.0.2 through
3.1.1 with **NTLMv2 and Kerberos (GSS-API/SPNEGO) authentication, SMB2/3
signing, SMB 3.1.1 preauth integrity, SMB3 multichannel, and SMB3 encryption
(AES-128/256-GCM, AES-128/256-CCM)**, plus a user database, optional guest
access, byte-range locks, leases (read- and handle-caching) and directory change
notification.

Large unsigned file reads never copy through userspace: the response header is
written and the kernel then moves the file's page-cache pages straight into the
socket through splice(2).

## Status

**Stable (`1.4`).** The configuration format and the on-wire behaviour match the
1.x feature level the server implements; the SMB2 frame entry point, the NTLMSSP
parser, the SPNEGO/GSS classifier and the lease-context walker are fuzzed.

- **Memory safe by construction.** The whole module is pure Go. CI rejects any
  change that introduces `import "C"` or `unsafe`, and builds with
  `CGO_ENABLED=0` to prove it.
- **Authorization is share-level only.** Once authenticated, any user can use
  every share (`read_only` applies to everyone), and all file I/O runs as the
  server's own Unix user. Per-share user/group lists are not implemented — run
  the server as a dedicated unprivileged user that owns only the share trees.
- **No SMB1.** Every SMB1 NEGOTIATE gets the SMB2 wildcard (0x02FF) reply, and
  the dialects a client offers are not checked. An SMB2-capable client upgrades
  normally; an SMB1-only client (e.g. some BMCs) cannot parse the reply and
  hangs until it times out (~20 s) instead of being refused.
- **Kerberos single-leg only.** The acceptor handles a complete AP-REQ exchange
  (what cifs.ko and Windows send). A multi-leg exchange is logged and rejected.

Set `encrypt = true` to require encryption, or just mount with `seal` (Linux) /
an encrypted share (Windows). `prefer_aes256` selects AES-256 when offered.
Read-caching + handle-caching leases are on by default (`oplocks`). SMB Direct
(RDMA) is on the [roadmap](docs/SMBDIRECT.md). See [SECURITY.md](SECURITY.md).

## Performance

Two suites measure the server, and both are in this repository:

- **`go test -bench .`** — in-repository benchmarks. The `BenchmarkServer*`
  entries drive a real SMB2 client against a running server over TCP and report
  throughput directly (bytes/op); the rest are per-message codec and crypto
  costs. These run anywhere, including CI.
- **`bench/bench.sh`** — the end-to-end suite for a real host: it mounts the
  server through cifs.ko and measures sequential read, sequential write,
  parallel read, small-file metadata and integrity, and it can be pointed at a
  Samba instance for a like-for-like comparison. Requires root, port 445 and
  `cifs-utils`.
- **`bench/interop-smbclient.sh`** — drives a running server with Samba's own
  `smbclient` (no root needed) across the dialect matrix, md5-verified
  transfers, authentication and SMB3 encryption. This is the interop gate: it
  currently passes 13/13, and it is how several pipelining and encryption bugs
  were caught.

Measured on an Intel Core i7-8550U (4 cores / 8 threads), Linux 7.0, loopback,
one worker, with the benchmark client in the same process and one request in
flight:

| Benchmark | Result |
|---|---|
| sequential READ, 1 GiB in 1 MiB requests | **846 MB/s** |
| sequential WRITE, 512 MiB in 1 MiB requests | **553 MB/s** |
| zero-copy READ, 1 MiB requests | **968 MB/s** (1.08 ms/op) |
| buffered READ, 4 KiB requests | 785 µs/op (52 MB/s, latency-bound single stream) |
| WRITE, 1 MiB requests | **707 MB/s** (1.48 ms/op) |
| create + write + close (metadata) | 4 450 ops/s |
| AES-128-GCM seal+open, 64 KiB | 527 MB/s |
| AES-128-CCM seal+open, 64 KiB | 60 MB/s |
| SMB2 signing, AES-CMAC over 1 MiB | 342 MB/s |
| SMB2 signing, HMAC-SHA256 over 1 MiB | 274 MB/s |
| NTLM NT hash (MD4 of the password) | 585 ns/op |
| NTLMv2 HMAC-MD5 | 1.26 µs/op |
| SP800-108 KDF-128 (key derivation) | 2.29 µs/op |
| ECHO round trip through `ProcessFrame` | 193 ns/op, 1 alloc |
| directory snapshot, 256 entries | 804 µs/op |

The single-stream socket numbers include the benchmark client in the same
process and one request in flight at a time, so they are a floor, not a
ceiling: a real client keeps many reads outstanding, and multichannel spreads a
mount across cores. Record every run of the full suite in
[docs/BENCHMARKS.md](docs/BENCHMARKS.md); the method, the historical
like-for-like comparison against Samba, and the tuning findings are there too.

## Requirements

- **Linux.** The transport uses `SO_REUSEPORT`, `inotify`, OFD byte-range locks
  and the kernel's `splice(2)` path, and there is no non-Linux build.
- **Go 1.27 or newer** to build.
- **Capability to bind port 445** (`CAP_NET_BIND_SERVICE`, or run as root).
  TCP 445 (direct TCP, 4-byte NetBIOS length framing) is the only transport:
  there is no NetBIOS (139), no RPC or management API, and no SMB Direct (RDMA).

## Build

```sh
go build ./cmd                # the server binary
go test ./...                 # unit, protocol and socket-level tests
go test -race ./...           # the same, under the race detector
go test -run '^$' -fuzz FuzzProcessFrame -fuzztime 60s .   # fuzz the wire parser
go test -run '^$' -bench . .  # benchmarks
```

A static binary is the zero-effort default — that is the point of having no
CGO:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o samba ./cmd
```

### Container

`Containerfile` packages the static binary into a `scratch` image. It reads its
config from `/etc/samba/samba.toml`, so mount that and your share directories
in, and publish port 445:

```sh
CGO_ENABLED=0 go build -trimpath -o samba ./cmd
podman build -t samba -f Containerfile .
podman run -d -p 445:445 -v /etc/samba:/etc/samba:ro -v /srv/data:/srv/data samba
```

## Configuration

TOML, passed with `--config <path>` (default `./samba.toml`). Unknown keys are
rejected, so a typo fails at startup instead of silently taking a default. A
full example — every key, commented — is in
[`samba.toml.example`](samba.toml.example).

The command reports what a configuration will actually do, from the same
introspection the server itself uses:

```sh
# validate a file, and report the settings and capabilities it enables
samba --check --config /etc/samba/samba.toml
# the resolved configuration, with every credential redacted
samba --dump-config --config /etc/samba/samba.toml
# the negotiation facts
samba --list-dialects
samba --list-ciphers
# the multichannel advertisement, after advertise_only
samba --list-interfaces --config /etc/samba/samba.toml
# override the file: overrides always win
samba --log-level 2 --listen 127.0.0.1:4455 --workers 4
```

At `log_level = 1` or above the same report is logged at startup, so the banner
and `--check` can never disagree about what a configuration means.

| Key | Default | Meaning |
|---|---|---|
| `listen` | `"0.0.0.0:445"` | Bind address (`ip:port`). |
| `workers` | `0` | Listener goroutines, each with its own `SO_REUSEPORT` listener. `0` = one per CPU core. |
| `server_name` | `"SAMBA"` | Advertised server name; also the default Kerberos SPN host (`cifs/<server_name>`). |
| `log_level` | `1` | `0` = warn, `1` = info, `2` = debug. |
| `allow_guest` | true if there are no `[[user]]` entries, else false | Allow unauthenticated guest sessions. |
| `require_signing` | `false` | Reject unsigned requests on authenticated sessions. |
| `encrypt` | `false` | Require SMB3 encryption for all post-auth traffic. When false, encryption a client asks for (e.g. cifs `seal`) is still honored. |
| `prefer_aes256` | `false` | Pick AES-256 (GCM, then CCM) when offered, instead of the client's order. |
| `multichannel` | `false` | Advertise SMB3 multichannel and accept session binding. |
| `advertise_only` | `[]` | Addresses to advertise for multichannel; empty = every non-loopback interface. |
| `oplocks` | `true` | Grant leases: read-caching and handle-caching (R/RH). Write-caching is never granted. |
| `max_connections` | `512` | Concurrent connections the server will serve. The main lever on worst-case memory use; `-1` removes the limit. |
| `auth` | `"both"` | `"ntlm"`, `"kerberos"` or `"both"` (Kerberos preferred). |
| `[kerberos]` | absent | `enabled` (default true), `keytab` (default `$KRB5_KTNAME`, then `/etc/krb5.keytab`), `spn` (default `cifs/<server_name>`), `realm` (parsed; the realm actually comes from the ticket). |
| `[[share]]` | at least one required | `name`, `path` (must be an existing directory), `read_only` (default false). `IPC$` is reserved. |
| `[[user]]` | none | `name` plus exactly one of `password` or `nt_hash` (32 hex chars). NTLM users only; Kerberos principals come from the KDC. |

```toml
listen = "0.0.0.0:445"
workers = 0
require_signing = true
multichannel = true

[[share]]
name = "data"
path = "/srv/data"

[[user]]
name = "alice"
password = "secret"        # or: nt_hash = "<32 hex chars>"
```

Run it with `samba --config /etc/samba/samba.toml`.

### Resource limits

Every client-controllable resource is bounded, so one misbehaving peer cannot
take the server down for everyone else. The limits are generous enough that no
real client notices them, and hitting one is a protocol error for that client
(`STATUS_INSUFFICIENT_RESOURCES`), never a crash or a wild allocation:

| Limit | Value | Why |
|---|---|---|
| `max_connections` | 512 | Goroutines, descriptors and buffered requests per connection. |
| request bytes buffered per connection | one maximum frame (4.4 MiB) | A peer that stops reading cannot make the server buffer unboundedly. |
| sessions per connection | 64 | One session per connection is the norm; this stops one peer draining the server. |
| sessions overall | 65536 | Each carries a handle table. |
| open handles per session | 16384 | Protects the process descriptor table. |
| tree connects per session | 4096 | — |
| pending `CHANGE_NOTIFY` per connection | 256 | Each costs an inotify watch, and the kernel budget is per-user. |
| leases per file / overall | 64 / 65536 | Handle-caching leases outlive CLOSE. |
| `QUERY_DIRECTORY` pattern length | 255 characters | Windows' own limit, and it bounds wildcard matching. |

Timeouts bound the other direction: a peer that starts a frame and stops has 5
minutes to finish it, a peer that stops reading a response has 5 minutes per
write, and a zero-copy read is abandoned if it makes no progress for 5 minutes.
An idle connection is never disconnected. See
[REVIEW.md](REVIEW.md) for the review that produced these numbers and
[docs/TUNING.md](docs/TUNING.md) for sizing advice.

## Mounting

```sh
# Guest (when allowed)
mount -t cifs //server/data /mnt -o guest,vers=3.0

# NTLMv2, signed, SMB 3.1.1
mount -t cifs //server/data /mnt -o username=alice,password=secret,vers=3.1.1,sec=ntlmsspi

# Encrypted
mount -t cifs //server/data /mnt -o username=alice,password=secret,vers=3.1.1,seal

# Kerberos (needs a ticket: kinit alice@REALM)
mount -t cifs //server.example.com/data /mnt -o sec=krb5,vers=3.1.1

# Multichannel (server has multichannel = true)
mount -t cifs //server/data /mnt -o username=alice,password=secret,vers=3.1.1,multichannel,max_channels=4
```

## Using the package

`github.com/malivvan/samba` is a library as well as a server. The interesting
entry points are `ProcessFrame` (bytes in, response bytes or a zero-copy read
plan out), the `Server` type, the configuration model
(`LoadConfig`/`ParseConfig`), and `EncodeInterfaceInfo` for the multichannel
interface advertisement.

For operational tooling there is an introspection API, and the CLI is built
entirely on it: `Dialects()` and `Ciphers()` report the negotiation facts,
`Srv.Capabilities()` what a configuration enables, `Server.Stats()` the live
connection, session, handle, tree and lease counts, and `AdvertisedInterfaces()`
the multichannel advertisement. See the package documentation:

```sh
go doc github.com/malivvan/samba
```

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | process/worker/connection layout, the zero-copy read path, batching |
| [docs/SAMBA.md](docs/SAMBA.md) | the consolidated SAMBA/SMB2-3 specification this server is written against |
| [ROADMAP.md](ROADMAP.md) | what is not implemented yet, grouped by spec section, with the reason |
| [docs/TESTING.md](docs/TESTING.md) | unit, integration and socket tests, fuzzing, CI, the host suites |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | benchmark method, measured numbers, tuning findings |
| [docs/TUNING.md](docs/TUNING.md) | jumbo frames, TCP buffers, NIC/RSS, multichannel |
| [docs/OPLOCKS.md](docs/OPLOCKS.md) | leases: what is granted, when it breaks, cross-worker delivery |
| [docs/KERBEROS.md](docs/KERBEROS.md) | keytabs, SPNs, `auth`, troubleshooting |
| [docs/FIPS.md](docs/FIPS.md) | FIPS 140-3 mode and what it does and does not cover |
| [docs/CONCURRENCY.md](docs/CONCURRENCY.md) | why requests within one connection stay serialized |
| [docs/SMBDIRECT.md](docs/SMBDIRECT.md) | SMB Direct (RDMA) design sketch — not implemented |
| [docs/PORTING.md](docs/PORTING.md) | how this code maps onto the Rust implementation it is verified against, and every deliberate divergence |
| [docs/samba.8](docs/samba.8) | man page |

## License

MIT — see [LICENSE](LICENSE).
