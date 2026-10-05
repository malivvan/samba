# samba — project context for agents

A from-scratch SMB2/SMB3 file server (an `smbd` replacement) written in **pure
Go**. It parses untrusted network input and then serves files, so two rules
dominate every change: stay memory safe, and never trust a length, offset or
count that arrived on the wire.

## Goal: safe on the public internet

**The point of this project is a file server you can expose to the public
internet without putting the host at risk.** That is the objective every design
trade-off here is measured against, and it has concrete consequences:

- Compatibility is not a reason to accept a weakness. Where an old protocol or
  cipher exists only so that a legacy peer can connect, the answer is to refuse
  the peer, not to weaken the server. **SMB1 is not supported and never will
  be**: its useful surface is a catalogue of historical vulnerabilities and
  every client that matters has spoken SMB2/3 for years. Today an SMB1 NEGOTIATE
  gets the SMB2 wildcard so an SMB1-only client times out; refusing it explicitly
  is a roadmap item, not a feature request.
- A security setting is a **guarantee, not a hint**. `min_dialect` refuses a
  client below the floor rather than downgrading to it, and `encrypt = true`
  refuses a session it cannot encrypt rather than serving it in the clear. If
  you add a knob, make the weak branch impossible rather than unlikely.
- Being *reachable* is the design point, so the limits (see `limits.go`) and the
  panic guards are load-bearing, not defensive decoration.

**This is an objective, not yet a warranty.** No external security review has
been done — it is the top item in ROADMAP.md — and nothing in this repository
should be read as claiming otherwise. Keep SECURITY.md honest about that.

## Version

- Current: **1.4.0**, reported by the `Version` constant in `doc.go` (the single
  source of truth) and surfaced by `samba --version`.
- The version tracks the SMB feature level the server implements, not the age of
  the code: SMB 2.0.2–3.1.1, NTLMv2, signing, preauth integrity, multichannel,
  encryption and leases.

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
  go build ./...                       # the package and cmd
  go vet ./...
  go test ./...                        # unit + protocol + socket tests
  go test -race ./...                  # the same under the race detector
  go test -run '^$' -fuzz FuzzProcessFrame -fuzztime 30s .
  go test -run '^$' -bench . -benchtime 1s .
  gofmt -l .                           # must print nothing
  ```
- **Dependencies** are deliberately few and all pure Go: `BurntSushi/toml` (the
  configuration file) and `golang.org/x/sys/unix` (Linux syscalls). Adding a
  dependency needs a reason that the standard library cannot satisfy.
- **How it ships**: `Containerfile` builds a static binary into a `scratch`
  image; `pack/` carries the systemd unit and the distro metadata. Ports:
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

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) is the full design. The file map,
for where each concern lives:

| File | Contents |
|---|---|
| `doc.go` | package documentation and the version constant |
| `wire.go` | little-endian wire primitives (Reader/Writer, UTF-16LE) |
| `smb2.go` | SMB2 header codec, compound dispatch, transform header, `ProcessFrame` |
| `handlers.go` | command handlers (negotiate, session setup, tree, create, read/write, dir, info, lock, notify, ioctl, leases) |
| `server.go` | transport: SO_REUSEPORT listeners, per-connection goroutines, zero-copy READ, worker mailboxes |
| `zerocopy.go` | the splice(2) read path |
| `notify.go` | inotify watcher backing CHANGE_NOTIFY |
| `session.go` | cross-connection session registry (multichannel) |
| `lease.go` | file-keyed lease table and cross-worker break mailbox |
| `vfs.go` | filesystem layer: path resolution, handle table, metadata |
| `pattern.go` | DOS wildcard matching for QUERY_DIRECTORY |
| `crypto.go`, `cmac.go`, `ccm.go`, `md4.go` | signing, KDF and AEAD primitives |
| `ntlm.go`, `spnego.go` | NTLMv2 and the SPNEGO glue that classifies the security blob |
| `auth.go` | session establishment, shared by every mechanism |
| `config.go` | TOML configuration and the resolved server context, including the dialect floor |
| `limits.go` | every bound on a client-controllable resource |
| `introspect.go` | the published facts: the dialect table and floor, ciphers, per-config capabilities, live stats |
| `netinfo.go` | interface enumeration for multichannel |
| `status.go`, `log.go` | NTSTATUS codes and logging |
| `cmd/` | the command-line entry point |
| `docs/` | architecture, the SAMBA specification, benchmark, testing, tuning and security notes |
| `bench/` | host scripts: benchmark suite, stress/soak, Windows interop |
| `pack/` | the systemd unit and the distro metadata |

## Implemented surface

Protocol: NEGOTIATE (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1 with preauth integrity),
SESSION_SETUP (NTLMv2, guest/anonymous, multichannel channel binding),
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
- Kerberos, deliberately and permanently for now — see the authentication note
  below.

## Authentication

**NTLMv2 is the only mechanism, and that is deliberate.** Kerberos was removed
from this server entirely, together with its dependency (`jcmturner/gokrb5/v8`
and that package's whole transitive tree — the module now has two dependencies,
`BurntSushi/toml` and `golang.org/x/sys`).

The reasoning, recorded here because it is the kind of decision that looks like
an omission later:

- **The users are mainly not corporate.** This is a small file server meant to
  be reachable from the internet, not a member server in a managed realm.
  Kerberos only earns its keep next to a KDC; without one it is a great deal of
  code — and a large dependency tree — that never runs.
- **It is meant to run on the internet without compromising security.**
  Kerberos deployments in practice still fall back to RC4-HMAC (etype 23) for
  the principals that need it, and that cipher has known weaknesses. Not
  shipping Kerberos removes the temptation to accept it.
- **One mechanism is one code path.** `spnego.go` only classifies the security
  blob; the handshake is `ntlm.go`; everything after "this peer is user X with
  key K" is `auth.go`. Two mechanisms meant two versions of each.

`allow_guest` still enables anonymous sessions. There is no `auth` setting: with
one mechanism there is nothing to select. A configuration that still carries
`auth` or `[kerberos]` is rejected as an unknown key, so an old file fails
loudly instead of silently losing its policy.

**If Kerberos is needed again**, the intended shape is an exported
`Authenticator` interface that a caller registers, so the package is not
hard-wired to whichever mechanisms it happens to ship. The seam already exists:
`sessionSetup` (`handlers.go`) chooses a mechanism, a mechanism turns a client
token into a `sessionAuth` — an identity and its key, or a guest — and `auth.go`
does the rest: the connection and session bounds, installing the key, deriving
the signing and encryption contexts, and writing the response. Nothing in
`auth.go` mentions NTLM. That interface is deliberately **not** added yet: an
abstraction designed against exactly one implementation is usually the wrong
one.

One piece of Kerberos stays: the **OIDs** (`oidKrb5`, `oidMSKrb5`, `mechKrb5` in
`spnego.go`). They are recognized solely so a Kerberos token is refused with
`STATUS_NOT_SUPPORTED` rather than falling through to the NTLM handler, which
reads "no NTLMSSP token" as an anonymous peer and would hand it a guest session
wherever `allow_guest` is set. `TestSessionSetupRefusesKerberos` pins that, and
`TestHintAdvertisesNtlmOnly` pins that Kerberos is never advertised in NEGOTIATE.

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
- **Introspection is a contract.** The CLI describes the server from
  `introspect.go` (`Dialects`, `Ciphers`, `Srv.Capabilities`, `Server.Stats`,
  `AdvertisedInterfaces`) and never from strings written in `cmd/`. A new
  dialect, cipher or capability goes in that file, with a test in
  `introspect_test.go` pinning it to the code that acts on it — otherwise
  `--check`, the banner and the man page drift apart.
- **Commit style**: conventional commits (`feat:`, `fix:`, `perf:`, `docs:`,
  `chore:`), one logical change each, with `CHANGELOG.md` updated.

## Security posture (1.4)

NTLMv2 with a local user database, optional guest access, SMB2/3 signing,
SMB 3.1.1 preauth integrity, and SMB3 encryption (AES-128/256-GCM/CCM).
**Authorization is share-level only** and all I/O runs as
the server's Unix user. Symlinks inside a share are followed even outside it, as
in Samba's `wide links`.

The dialect floor matters to the posture, so it is worth stating together with
the rest: SMB 2.0.2 and 2.1 have **no encryption and no downgrade protection**,
so `min_dialect = "3.0"` (or `encrypt = true`, which implies it) is the setting
that removes both. `SECURITY.md` spells out the consequences.

No external security review has been done. The goal is a server that is safe to
expose, but that goal is the direction of travel and not a warranty: until a
review happens, treat 445 as untrusted-network-facing only with signing and
encryption on. Details and the reporting process are in [SECURITY.md](SECURITY.md).

## Not part of the codebase

Anything describing a different project's history, release engineering, build
farm or issue tracker does not belong here. This repository is the Go server:
the code, its tests, its benchmarks and its docs.
