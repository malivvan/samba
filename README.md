# samba

[![CI](https://github.com/malivvan/samba/actions/workflows/ci.yml/badge.svg)](https://github.com/malivvan/samba/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/malivvan/samba.svg)](https://pkg.go.dev/github.com/malivvan/samba)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A from-scratch SMB2/SMB3 file server (an `smbd` replacement) written in **pure
Go** — no CGO, no `unsafe`, anywhere in the module. It speaks SMB 2.0.2 through
3.1.1 with **NTLMv2 authentication, SMB2/3 signing, SMB 3.1.1 preauth
integrity, SMB3 multichannel, and SMB3 encryption (AES-128/256-GCM,
AES-128/256-CCM)**, plus a user database, optional guest access, byte-range
locks, leases (read- and handle-caching) and directory change notification.

Large unsigned file reads never copy through userspace where the platform allows
it: the response header is written and the kernel then moves the file's
page-cache pages straight into the socket (`splice(2)` on Linux, `sendfile(2)` on
macOS and the BSDs, a buffered copy on Windows). Which mechanism this build got
is printed by `samba --list-platform`, and the whole picture — including the
places a platform falls back — is the [support table](#platform-support) below.

## What this is for

The goal is a file server you can **expose to the public internet** without
putting the host at risk. That shapes the defaults: compatibility is never a
reason to accept a weakness, every client-controllable resource is bounded, and
a security setting is a guarantee rather than a hint. Two consequences worth
knowing up front:

- **SMB1 is not supported, and never will be.** Its useful surface is a
  catalogue of historical vulnerabilities, and every client that matters has
  spoken SMB2/3 for years. An SMB1-only client gets the SMB2 wildcard response
  and times out rather than being served.
- **SMB 2.x has no encryption and no downgrade protection.** `min_dialect =
  "3.0"` drops it entirely, and `encrypt = true` implies that floor — a client
  that cannot encrypt is refused, never served in the clear. See
  [SECURITY.md](SECURITY.md).

No external security review has been done yet: that is the direction of travel,
not a warranty.

> ### NTLMv2 only: Kerberos was removed
>
> This server authenticates with **NTLMv2, and nothing else**. Kerberos support
> was deleted outright, along with the `jcmturner/gokrb5` dependency and its
> whole transitive tree.
>
> The reasoning is that this server is meant mainly for **non-corporate users**,
> and to be **reachable from the internet without compromising security**.
> Kerberos only pays for itself beside a KDC, and the deployments that do need
> it still fall back to RC4-HMAC (etype 23), which has known weaknesses — so
> shipping it means shipping that option. `allow_guest` is still there for
> anonymous access, and there is no `auth` setting to select: with one mechanism
> there is nothing to choose.
>
> If Kerberos is needed later, the intent is to add an exported `Authenticator`
> interface that registers additional mechanisms, rather than hard-wiring
> another one. See [AGENTS.md](AGENTS.md) for the full note.

## Status

**Stable (`1.4`).** The configuration format and the on-wire behaviour match the
1.x feature level the server implements; the SMB2 frame entry point, the NTLMSSP
parser, the SPNEGO classifier and the lease-context walker are fuzzed.

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
- **NTLMv2 is the only mechanism.** Kerberos was removed deliberately — see the
  note above. A client offering only Kerberos is refused with
  `STATUS_NOT_SUPPORTED`, never downgraded to a guest session.

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

- **A supported platform**: Linux, macOS, FreeBSD, OpenBSD, NetBSD, DragonFly
  BSD or Windows. The four facilities the transport and filesystem layer need
  from the host each have a native implementation on some of those and a
  documented fallback on the rest — see [Platform support](#platform-support)
  for the mechanism per platform, the caveats that follow from it, and what CI
  actually verifies where.
- **Go 1.27 or newer** to build.
- **Capability to bind port 445** (`CAP_NET_BIND_SERVICE`, or run as root).
  TCP 445 (direct TCP, 4-byte NetBIOS length framing) is the only transport:
  there is no NetBIOS (139), no RPC or management API, and no SMB Direct (RDMA).

## Platform support

The server needs four things from the host that pure Go does not provide —
sharing a listening port between workers, watching a directory for changes,
locking a byte range, and moving file bytes to a socket — plus the file metadata,
timestamps and filesystem sizes the protocol reports. Each lives in its own
package under [`pkg/`](pkg) with one implementation per platform and a *real*
fallback where the platform has nothing sound: the rule is that a platform gets
the native mechanism where the mechanism is sound, and a documented, visible
degradation where it is not, never a fallback that pretends.

`✓` is a native mechanism; `~` is a documented fallback.

| Facility | Linux | macOS | FreeBSD | OpenBSD | NetBSD | DragonFly | Windows |
|---|---|---|---|---|---|---|---|
| Shared listening port | ✓ `SO_REUSEPORT` | ✓ `SO_REUSEPORT` | ✓ `SO_REUSEPORT` | ✓ `SO_REUSEPORT` | ✓ `SO_REUSEPORT` | ✓ `SO_REUSEPORT` | ~ one shared listener ⁽¹⁾ |
| Directory change notification | ✓ `inotify` | ✓ `kqueue` ⁽²⁾ | ✓ `kqueue` ⁽²⁾ | ✓ `kqueue` ⁽²⁾ | ✓ `kqueue` ⁽²⁾ | ✓ `kqueue` ⁽²⁾ | ✓ `ReadDirectoryChangesW` ⁽³⁾ |
| Byte-range locking | ✓ OFD locks ⁽⁴⁾ | ~ in-process ⁽⁵⁾ | ~ in-process ⁽⁵⁾ | ~ in-process ⁽⁵⁾ | ~ in-process ⁽⁵⁾ | ~ in-process ⁽⁵⁾ | ✓ `LockFileEx` ⁽⁴⁾⁽¹¹⁾ |
| File → socket | ✓ `splice(2)` | ✓ `sendfile(2)` ⁽¹⁰⁾ | ✓ `sendfile(2)` ⁽¹⁰⁾ | ✓ `sendfile(2)` ⁽¹⁰⁾ | ✓ `sendfile(2)` ⁽¹⁰⁾ | ✓ `sendfile(2)` ⁽¹⁰⁾ | ~ buffered copy ⁽⁶⁾ |
| File metadata | ✓ `stat(2)` | ✓ `stat(2)` | ✓ `stat(2)` | ✓ `stat(2)` | ✓ `stat(2)` | ✓ `stat(2)` | ✓ `GetFileInformationByHandle` ⁽⁷⁾ |
| Timestamps | ✓ `utimensat(2)`, ns | ✓ `futimes(2)`, µs ⁽⁸⁾ | ✓ `futimes(2)`, µs ⁽⁸⁾ | ✓ `futimes(2)`, µs ⁽⁸⁾ | ✓ `futimes(2)`, µs ⁽⁸⁾ | ✓ `futimes(2)`, µs ⁽⁸⁾ | ✓ `SetFileTime`, 100 ns |
| Filesystem size | ✓ `fstatfs` | ✓ `fstatfs` | ✓ `fstatfs` | ✓ `fstatfs` | ✓ `statvfs` | ✓ `fstatfs` | ✓ `FILE_FS_SIZE_INFORMATION` |
| Read-ahead hint | ✓ `posix_fadvise` | ~ none ⁽⁹⁾ | ✓ `posix_fadvise` | ~ none ⁽⁹⁾ | ✓ `posix_fadvise` | ~ none ⁽⁹⁾ | ~ none ⁽⁹⁾ |

Two further platform groups are not supported but are worth naming, because what
they do is part of the same rule:

- **Solaris/illumos, JS and WASI** build and type-check with every fallback at
  once: polling notifications, the in-process lock registry, buffered reads, and
  an error (never an invented value) from the timestamp and filesystem-size
  calls. A JS/WASI build has no socket to serve on, so "builds" is the whole
  claim there; Solaris/illumos would run, degraded in the ways above, but nothing
  tests it.
- **Plan 9 and AIX do not build**, for a reason that predates the platform layer:
  `status.go` maps POSIX `errno` values that their `syscall` packages do not
  define. That is a one-file fix if anyone wants those targets; it is not
  pretended otherwise here.

Every facility reports which mechanism it got: `samba --list-platform` prints the
table above for the running binary, and `samba --check` reports it next to the
capabilities. `pkg/watch` also exposes its fallback explicitly
(`watch.NewPolling`), which is what lets the polling watcher be tested on every
platform rather than only on the ones that depend on it; the other three choose
their mechanism at compile time.

### Caveats

Every platform keeps the protocol guarantees — signing, encryption, preauth
integrity, the resource limits, the panic guards — because none of those are
platform-dependent. What differs is what the host can enforce or observe, and
these are the consequences worth knowing before deploying:

- ⁽¹⁾ **Windows has no `SO_REUSEPORT`; its `SO_REUSEADDR` is never set, and the
  listener is made exclusive instead.** The option called `SO_REUSEADDR` on
  Windows lets *another* socket forcibly bind an address that is already in use
  and take its connections, so setting it would be a downgrade rather than
  portability. Go's `net` package sets nothing for a Windows listener, so this is
  where the protection comes from: the server asks for
  **`SO_EXCLUSIVEADDRUSE`**, which is Windows' own answer to port hijacking and
  what Microsoft recommends for servers — with it, no other socket can bind the
  address, not even one asking for `SO_REUSEADDR`. Every worker then accepts from
  one shared socket, so the difference from the other platforms is only *who*
  balances the accepts (the runtime's accept mutex instead of the kernel), not
  how many connections the server can hold.
  The one cost is Microsoft's documented caveat that an exclusively bound port
  "cannot necessarily be reused immediately after socket closure" while old
  connections are still winding down; the shipped systemd unit restarts with a
  delay, and a startup that hits it fails with the bind error rather than
  silently serving on a port someone else could take.
- ⁽²⁾ **kqueue reports that a directory changed, not what changed.** The vnode
  filter is per vnode and a directory's vnode has no notion of which child
  moved; naming it would need FSEvents, which lives in a framework reachable
  only through cgo. A change here is delivered as "this directory changed" and
  the client is told to re-enumerate (`STATUS_NOTIFY_ENUM_DIR`), which is the
  protocol's own answer for it: correct, just more traffic. Two further
  consequences: a *content* change to an existing file inside the directory is
  not noticed at all (the directory's vnode does not change), and a rename
  arrives as an unattributable change rather than as its two halves.
- ⁽³⁾ **On Windows, deleting the watched directory itself may not be reported**
  while the server holds its handle: the handle keeps the directory alive, so
  the kernel never announces the removal. In practice a client that deletes a
  directory also closes its handle, and that close is what ends the pending
  `CHANGE_NOTIFY`, so the case does not hang.
- ⁽⁴⁾ **Linux and Windows enforce a lock against other local processes too** —
  the kernel's lock is taken on top of the server's own table, so a local process
  writing to a share file sees it. On Windows that mirror costs an extra step in
  every change; see ⁽¹¹⁾.
- ⁽⁵⁾ **macOS and the BSDs do not enforce a lock against local processes.** They
  have only classic POSIX record locks, which belong to the *process*: two
  handles of one file never conflict at the kernel, and closing any descriptor
  releases every lock the process holds on that file. Taking such a lock would be
  actively wrong (it would drop a sibling handle's lock), so it is not taken, and
  the server's own registry is authoritative instead. Locks are still enforced
  between SMB clients, which is what the protocol promises; what is missing is
  enforcement against a *local* process, exactly as Samba documents for
  `kernel oplocks`. **Do not mix local and SMB access to one share** on those
  platforms.
- ⁽⁶⁾ **Windows reads are copied through userspace.** Its equivalent of
  `sendfile(2)`, `TransmitFile`, applies the file's own offset rather than an
  explicit one and is limited to 32-bit request sizes on some paths, so it cannot
  serve a handle that several session channels read concurrently at different
  offsets. The copy is correct and bounded; a large sequential READ is simply not
  as fast as on the other platforms.
- ⁽⁷⁾ **File identity on Windows** comes from `GetFileInformationByHandle`, so a
  directory entry that cannot be opened has no identity; such an entry is simply
  not eligible for a lease (the protocol permits a file to be opened without
  one).
- ⁽⁸⁾ **A timestamp update on macOS or the BSDs is microsecond-precise and reads
  before it writes.** `futimes(2)` sets both timestamps at once and has no
  `UTIME_OMIT`, so a client that asks to change one of them has the other filled
  in from the file's current value — a one-syscall window in which a concurrent
  writer could race it, and only for the timestamp the client asked to leave
  alone. Linux uses `utimensat(2)` with `AT_EMPTY_PATH` and `UTIME_OMIT` and has
  neither limitation; Windows expresses "leave unchanged" as a null field.
- ⁽⁹⁾ **The read-ahead hint is a pure performance hint** and is skipped where the
  platform's call cannot be reached without `unsafe` (macOS `F_RDADVISE` takes a
  struct pointer) or does not exist. Nothing about the data a client receives
  changes; the kernel's own readahead still applies.
- ⁽¹⁰⁾ **On macOS and the BSDs, `sendfile(2)` reports a partial send together
  with the error.** A non-blocking `sendfile` queues what fits into the socket
  buffer and answers `EAGAIN` for the rest, with the out-length set to what it
  queued — unlike Linux and Solaris, which answer `(0, EAGAIN)` and nothing else.
  That is handled (the partial count is what the transfer's offset advances by),
  and it is worth knowing because the bug it prevents is silent: counting only
  the clean successes desynchronizes the offset and the client receives a
  response with duplicate bytes in it. Two related quirks are handled the same
  way: `sendfile` can also answer `EAGAIN` having sent *everything* it was asked
  for, and a *fatal* error may leave the length untouched, so its value is never
  believed. One consequence cannot be engineered around: XNU's `sendfile`
  allocates mbufs before it checks the non-blocking flag, so under mbuf pressure
  the call can park inside the kernel and the stall deadline cannot preempt it —
  it resumes once the allocation succeeds.
- ⁽¹¹⁾ **Windows locks are exact-match objects, and the server works around it.**
  A Windows byte-range lock can only be released with exactly the range it was
  taken with — no partial unlock, no release of two adjacent locks with one call
  — and a handle cannot take a range it already holds, so a shared lock cannot be
  upgraded in place and a client cannot re-lock what it holds (both are refused
  even for the same handle). A range whose offset plus length runs past the
  largest signed offset is refused outright. POSIX locks, and the protocol's own
  semantics, allow all of those.
  So on Windows the kernel's table is not updated in place: for each change the
  server computes the region affected, releases exactly the objects it took there,
  and takes exactly the ranges the registry wants in their place. Two consequences
  are worth knowing:
  - The *protocol* result is identical to every other platform — the registry
    decides what a client may lock, and it splits, merges and converts freely.
  - Because the kernel objects are rebuilt, another process touching the file can
    win a race for a range in the middle of a change. That makes the operation
    fail with `LOCK_NOT_GRANTED` (the client can retry), and if the range cannot
    be put back, that handle's locks stop being mirrored into the kernel — so they
    are enforced between SMB clients, which is the protocol's guarantee, but no
    longer against other local processes. `samba --list-platform` counts those
    events. Linux has no such window: its OFD locks are updated in place.
  - Windows also enforces a byte-range lock against *I/O* through other handles,
    so a WRITE from a second client to a range the first has locked fails with an
    I/O error. That is how Windows behaves, and a client of a Windows-hosted
    server sees it elsewhere too; on Linux such a write succeeds, because POSIX
    locks are advisory.
- **Creation time is synthesized from the modification time** on every platform:
  SMB has a creation time and no portable way to read one, so `mtime` is
  reported. Live with it or fix it per platform — it is not a platform
  difference.
- **Mixing local and SMB access to one share is unsupported everywhere**, because
  a lease held by an SMB client is not broken by a local process touching the
  file (there is no kernel-oplock integration). See [ROADMAP.md](ROADMAP.md).

### What CI verifies

| Platform | CI coverage |
|---|---|
| Linux | `gofmt`, `go vet`, a `CGO_ENABLED=0` build, the full test suite, the race detector, lint, coverage and fuzzing. The Linux leg is the gate. |
| macOS, Windows | `gofmt`, `go vet`, a `CGO_ENABLED=0` build of everything, **and `go test ./pkg/...`** — so kqueue, `sendfile`, `fstatfs`/`statvfs`, `futimes`, `ReadDirectoryChangesW`, `LockFileEx` and the `FILE_FS_SIZE_INFORMATION` path are *run*, not just compiled. |
| FreeBSD, OpenBSD, NetBSD, DragonFly BSD | Cross `go build` and `go vet` (`GOOS=… GOARCH=amd64`, `CGO_ENABLED=0`) of the whole module including tests. **Nothing runs them**: their code paths are compile-verified, not runtime-verified, and the table above states that rather than implying otherwise. |

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
| `workers` | `0` | Listener goroutines, each accepting independently: with `SO_REUSEPORT` each has its own socket on the port, and on a platform without it they share one. `0` = one per CPU core. |
| `server_name` | `"SAMBA"` | Advertised server name. |
| `log_level` | `1` | `0` = warn, `1` = info, `2` = debug. |
| `allow_guest` | true if there are no `[[user]]` entries, else false | Allow unauthenticated guest sessions. |
| `require_signing` | `false` | Reject unsigned requests on authenticated sessions. |
| `encrypt` | `false` | Require SMB3 encryption for all post-auth traffic. When false, encryption a client asks for (e.g. cifs `seal`) is still honored. |
| `prefer_aes256` | `false` | Pick AES-256 (GCM, then CCM) when offered, instead of the client's order. |
| `multichannel` | `false` | Advertise SMB3 multichannel and accept session binding. |
| `advertise_only` | `[]` | Addresses to advertise for multichannel; empty = every non-loopback interface. |
| `oplocks` | `true` | Grant leases: read-caching and handle-caching (R/RH). Write-caching is never granted. |
| `min_dialect` | `"2.0.2"`, or `"3.0"` when `encrypt = true` | Oldest dialect to negotiate (`"2.0.2"`, `"2.1"`, `"3.0"`, `"3.0.2"`, `"3.1.1"`). A client offering nothing at or above it is refused, not downgraded. |
| `max_connections` | `512` | Concurrent connections the server will serve. The main lever on worst-case memory use; `-1` removes the limit. |
| `[[share]]` | at least one required | `name`, `path` (must be an existing directory), `read_only` (default false). `IPC$` is reserved. |
| `[[user]]` | none | `name` plus exactly one of `password` or `nt_hash` (32 hex chars), checked by NTLMv2. There is no directory service behind it. |

```toml
listen = "0.0.0.0:445"
workers = 0
require_signing = true
min_dialect = "3.0"
multichannel = true

[[share]]
name = "data"
path = "/srv/data"

[[user]]
name = "alice"
password = "secret"        # or: nt_hash = "<32 hex chars>"
```

Run it with `samba --config /etc/samba/samba.toml`. For an internet-facing
deployment add `encrypt = true` and `allow_guest = false`; `encrypt` also raises
the dialect floor to 3.0 on its own.

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
| pending `CHANGE_NOTIFY` per connection | 256 | Each costs a watch in the platform's own table (`inotify`, `kqueue`, a completion port), and that budget is shared with every other process on the host. Several pends on one directory share a single watch. |
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

# Multichannel (server has multichannel = true)
mount -t cifs //server/data /mnt -o username=alice,password=secret,vers=3.1.1,multichannel,max_channels=4
```

Kerberos (`sec=krb5`) is not available: see the note at the top.

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
| [docs/FIPS.md](docs/FIPS.md) | FIPS 140-3 mode and what it does and does not cover |
| [docs/CONCURRENCY.md](docs/CONCURRENCY.md) | why requests within one connection stay serialized |
| [docs/SMBDIRECT.md](docs/SMBDIRECT.md) | SMB Direct (RDMA) design sketch — not implemented |
| [docs/PORTING.md](docs/PORTING.md) | how this code maps onto the Rust implementation it is verified against, and every deliberate divergence |
| [docs/samba.8](docs/samba.8) | man page |

## License

MIT — see [LICENSE](LICENSE).
