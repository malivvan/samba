# samba — project context for agents

A from-scratch SMB2/SMB3 file server (an `smbd` replacement) written in **pure
Go**. It parses untrusted network input and then serves files, so two rules
dominate every change: stay memory safe, and never trust a length, offset or
count that arrived on the wire.

## Version

- Current: **1.4.0**, reported by the `Version` constant in `doc.go` (the single
  source of truth) and surfaced by `samba --version`.
- The version tracks the SMB feature level the server implements, not the age of
  the code: SMB 2.0.2–3.1.1, NTLMv2 + Kerberos, signing, preauth integrity,
  multichannel, encryption and leases.

## Platform and build

- **Linux only.** The transport and filesystem layer use `SO_REUSEPORT`,
  `inotify`, OFD byte-range locks, `statfs`, `futimens` and the kernel's
  `splice(2)` path, all through `golang.org/x/sys/unix`. There is no
  non-Linux build and adding one is not a goal.
- **Pure Go, always.** No CGO, no `unsafe`, in any file that ships. CI builds
  with `CGO_ENABLED=0` and greps for both. If a feature seems to need a C
  library, that is a signal to implement it in Go (as was done for AES-CMAC,
  AES-CCM and MD4) or to use a pure-Go module — not to add a build constraint.
- **Toolchain**: Go 1.27 or newer (the `go` directive in `go.mod` is newer still
  because `golang.org/x/sys` requires it).
- **Commands** (there is no Makefile; the Go toolchain is the build system):
  ```sh
  go build ./...                       # the package and cmd/samba
  go vet ./...
  go test ./...                        # unit + protocol + socket tests
  go test -race ./...                  # the same under the race detector
  go test -run '^$' -fuzz FuzzProcessFrame -fuzztime 30s .
  go test -run '^$' -bench . -benchtime 1s .
  gofmt -l .                           # must print nothing
  ```
- **Dependencies** are deliberately few and all pure Go: `BurntSushi/toml` (the
  configuration file), `golang.org/x/sys/unix` (Linux syscalls) and
  `jcmturner/gokrb5/v8` (the Kerberos/KDC wire protocol for the acceptor).
  Adding a dependency needs a reason that the standard library cannot satisfy.
- **How it ships**: `Containerfile` builds a static binary into a `scratch`
  image; `packaging/` carries the systemd unit and the distro metadata. Ports:
  TCP 445 only — no NetBIOS 139, no RPC, no HTTP health endpoint.

## Architecture

```
main ─ config (TOML) ─ NewServer ─ N workers (SO_REUSEPORT listeners)
each worker goroutine:
  Accept() ─► one goroutine per connection
                ├─ reader goroutine: NBT framing ─► frames channel
                ├─ driver goroutine: ProcessFrame per frame, responses batched
                │                   into one write; zero-copy READ plans are
                │                   served by header write + splice(file→socket)
                ├─ notifier goroutine: inotify watches ─► deferred completions
                └─ deferred queue: server-initiated frames (lease breaks,
                                   CHANGE_NOTIFY completions) written by the
                                   driver goroutine, never concurrently
shared across workers (in Srv): session registry, per-session handle table,
lease table, per-worker break mailboxes
```

The one invariant to protect: **a connection's socket has exactly one writer.**
Responses, lease breaks and notify completions are all funnelled through the
driver goroutine (the deferred queue exists for precisely that reason). Anything
that writes to `conn.nc` from another goroutine is a bug.

Read the file map in [CONTRIBUTING.md](CONTRIBUTING.md) for where each concern
lives, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## Implemented surface

Protocol: NEGOTIATE (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1 with preauth integrity),
SESSION_SETUP (NTLMv2, Kerberos, guest/anonymous, multichannel channel binding),
LOGOFF, TREE_CONNECT/DISCONNECT (`IPC$` stub), CREATE (including `RqLs` lease
contexts), CLOSE, FLUSH, READ (zero-copy or buffered), WRITE, QUERY_DIRECTORY
(six information classes), QUERY_INFO (file, filesystem and a synthesized
security descriptor), SET_INFO (rename, delete-on-close, truncate, timestamps),
LOCK (OFD byte-range locks, all-or-nothing batches), IOCTL
(`FSCTL_VALIDATE_NEGOTIATE_INFO`, `FSCTL_QUERY_NETWORK_INTERFACE_INFO`),
CHANGE_NOTIFY (real inotify-backed async completion), CANCEL, ECHO, compound
requests, credit accounting, SMB3 transform-header encryption and SMB2/3 signing.

Not implemented, and each has a reason recorded in `docs/` or `SECURITY.md`:

- per-share authorization / SID→uid mapping (share-level `read_only` only),
- write-caching leases (they need break-with-acknowledgement),
- intra-connection request concurrency (measured as unnecessary, see
  `docs/CONCURRENCY.md`),
- SMB Direct / RDMA (design sketch only, `docs/SMBDIRECT.md`),
- multi-leg Kerberos exchanges.

## Working rules

- **Keep `ProcessFrame` pure.** Everything it needs is passed in; it must stay
  callable from a fuzz target with no sockets and no synchronization.
- **New wire behaviour needs a test.** Drive `ProcessFrame` and assert on bytes
  (`smb2_test.go`), or drive a real socket (`server_test.go`). A parser change
  also gets a few seconds of fuzzing before it lands.
- **Never trust client-supplied offsets/lengths.** Every decode path uses the
  bounds-checked `Reader`; slice arithmetic on wire data goes through
  `sliceAt`. A panic on malformed input is a security bug — and if one is ever
  reachable, the per-connection panic guard contains it rather than taking the
  process down.
- **Every client-controllable resource has a bound.** Add new ones to
  `limits.go` with a comment explaining what a peer could otherwise do, and
  answer `STATUS_INSUFFICIENT_RESOURCES` when it is hit. Equally, every wait has
  a timeout, and an *idle* connection is never disconnected. [REVIEW.md](REVIEW.md)
  is the record of the review that established this.
- **Offset discipline in the read path.** SMB reads are addressed by offset and
  a handle can be read concurrently from several channels of one session, so
  file access uses positional I/O (`ReadAt`/`WriteAt`, explicit-offset
  `splice(2)`). Nothing may depend on, or disturb, a file descriptor's own
  position.
- **Share the session lock briefly.** Trees and handles live behind the session
  lock; file I/O must not happen with it held.
- **Document as you go.** Any perf-relevant change gets re-measured with the
  benchmarks and recorded in `docs/BENCHMARKS.md`; architecture changes update
  `docs/ARCHITECTURE.md` in the same change.
- **Commit style**: conventional commits (`feat:`, `fix:`, `perf:`, `docs:`,
  `chore:`), one logical change each, with `CHANGELOG.md` updated.

## Security posture (1.4)

NTLMv2 (+ Kerberos) with a local user database, optional guest access, SMB2/3
signing, SMB 3.1.1 preauth integrity, and SMB3 encryption
(AES-128/256-GCM/CCM). **Authorization is share-level only** and all I/O runs as
the server's Unix user. Symlinks inside a share are followed even outside it, as
in Samba's `wide links`. No external security review has been done: do not
expose 445 to the public internet. Details and the reporting process are in
[SECURITY.md](SECURITY.md).

## Not part of the codebase

Anything describing a different project's history, release engineering, build
farm or issue tracker does not belong here. This repository is the Go server:
the code, its tests, its benchmarks and its docs.
