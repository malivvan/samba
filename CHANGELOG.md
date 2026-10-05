# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
conventional commits.

## [Unreleased]

### Kerberos removed

- **Kerberos is gone, and so is its dependency.** NTLMv2 is now the only
  authentication mechanism, `allow_guest` still enables anonymous sessions, and
  the `auth` setting is gone entirely. The module no longer imports
  `jcmturner/gokrb5/v8`, nor the transitive tree it dragged in (`aescts`,
  `dnsutils`, `gofork`, `goidentity`, `rpc`, `go-uuid`, and through them
  `golang.org/x/crypto` and `golang.org/x/net`) — exactly two dependencies
  remain: `BurntSushi/toml` and `golang.org/x/sys`.
- The reasoning is recorded in full in [AGENTS.md](AGENTS.md): this server is
  aimed mainly at non-corporate users and at being reachable from the internet,
  and real Kerberos deployments still lean on RC4-HMAC (etype 23), which has
  known weaknesses. Shipping Kerberos meant shipping that option. If it is
  needed later, the intent is an exported `Authenticator` interface that
  registers additional mechanisms rather than a re-vendored acceptor.
- **A Kerberos token is now refused explicitly, not downgraded.** The
  `mechKrb5` case and the Kerberos OIDs stay in `spnego.go` so `sessionSetup`
  can answer `STATUS_NOT_SUPPORTED`: without it the token would fall through to
  the NTLM handler, which reads "no NTLMSSP token" as an anonymous peer and
  would hand it a guest session wherever `allow_guest` is set.
  `TestSessionSetupRefusesKerberos` pins that, and `TestHintAdvertisesNtlmOnly`
  pins that Kerberos is never advertised in NEGOTIATE.
- **A configuration that still carries `auth` or `[kerberos]` now fails at
  startup** as an unknown key, instead of starting with the operator's
  authentication policy silently dropped.
- **The shared half of the authentication path was extracted** into `auth.go`.
  `sessionSetupCtx` decodes the request once, and `establish` installs the
  identity and its key, derives the signing and encryption contexts for the
  negotiated dialect, and writes the response — for every mechanism, which is
  the seam a future `Authenticator` interface would plug into.
- Removed along the way: `docs/KERBEROS.md`, `bench/krb5/e2e.sh`, the `krb5.go`
  acceptor with its tests, and the `auth`/`[kerberos]` material from the example
  configuration, the man page, `--dump-config` and the distro packages.

### Repository layout, CLI and introspection

- **`cmd/samba/` became `cmd/`**, so `go build ./cmd` is the server binary, the
  usual shape for a single-command module. Every reference was updated: the
  `bench/` scripts, the systemd/deb/RPM recipes, the man page, the docs, the
  README and CI.
- **`SPEC.md` moved to [docs/SAMBA.md](docs/SAMBA.md)** and **`packaging/` was
  renamed to `pack/`**. `CONTRIBUTING.md` is gone; its file map now lives in
  `AGENTS.md`, next to the rest of the project context.
- **The CLI is now a report on the server, not just a launcher.** `--check`
  validates a configuration and prints the resolved settings, every capability
  it enables, the shares and the users; `--dump-config` prints the resolved
  configuration as TOML with every password and NT hash redacted;
  `--list-dialects`, `--list-ciphers` and `--list-interfaces` print the
  negotiation facts; `--log-level`, `--listen` and `--workers` override the file;
  `--help` documents all of it. At `log_level = 1` or above the startup banner
  logs the same report, so the banner and `--check` cannot disagree.
- **New introspection API**, which is what the CLI is built on and what
  operational tooling can use: `Dialects`, `Ciphers`, `SigningAlgorithms`
  (the negotiation facts), `Srv.Capabilities()` (what a configuration enables),
  `Server.Stats()` (live connections, sessions, handles, trees and leases),
  `AdvertisedInterfaces()` (the multichannel advertisement), and the
  `Registry.Len`/`Registry.Totals`/`LeaseTable.Len` counters underneath.
  `NEGOTIATE` now takes its cipher preference order from that same list, so what
  is published is what is applied. `introspect_test.go` pins each published list
  to the code that consumes it.
- **`samba.toml.example` is a working, fully commented configuration again.** It
  had drifted to a developer's own paths and settings, which meant
  `TestShippedExampleConfigLoads` only passed on a machine that happened to have
  that directory — on a fresh checkout, and so in CI, it would have failed. The
  example uses the documented placeholders, and the test now says so explicitly
  when the placeholder is missing instead of failing obscurely later.

### Security and stability review

A full review of the package (see [REVIEW.md](REVIEW.md)) found and fixed 22
issues, most of them ways a single peer could exhaust a shared resource or hold
one forever:

- **Resource limits** (`limits.go`): connections (`max_connections`, default
  512), sessions per connection and overall, open handles per session, tree
  connects, pending `CHANGE_NOTIFY` (which cost kernel inotify watches), leases
  per file and overall, and the buffered request bytes a connection may hold
  (one maximum-size frame — previously a peer could make the server buffer
  ~275 MiB per connection by not reading its responses).
- **Timeouts**: an incomplete frame must be finished within 5 minutes, a stalled
  response write is abandoned after 5 minutes without progress, and the
  zero-copy read pump gives up on a peer that stops making progress. An idle
  connection is never disconnected.
- **Panic isolation**: each connection and worker iteration now runs under a
  guard that logs the panic with a stack trace and tears down only that
  connection, so one malformed frame can no longer take the process (and every
  other client) down.
- **Log flooding**: warn-level output is rate limited, with a summary of how
  many messages were suppressed, so a peer cannot fill a log filesystem.
- **Read/close race**: a READ in flight on one channel is no longer cut short by
  a CLOSE on another (`OpenFile` reference counting).
- **Kerberos**: the acceptor (and its keytab read) is built once per server
  instead of once per logon, and an unusable keytab is reported at startup.
- Smaller fixes: no whole-directory read to test a directory for emptiness, an
  AES-CCM length-field guard, an optimized NTLMSSP token search, a stale handle
  count after bulk-closing a session, and a data race on the listener field.

### Tests

Test coverage went from 68% to 94% of statements, driven by tests for behaviour
rather than line counts: every SMB2 command and its parameter validation, every
decoder's error path (a truncation sweep), the session-setup policy and
multichannel binding paths, a complete Kerberos login built from a real keytab
and AP-REQ, the notifier and its inotify parsing, the resource limits, the
timeout/panic/reconnect paths, and the CLI.

### Continuous integration

- **One workflow** (`.github/workflows/ci.yml`) replaces the three that were
  split across `ci.yml`, `fuzz.yml` and `release.yml` — none of which had ever
  run, because all three were triggered on a `main` branch that does not exist
  here. It runs on every push, on pull requests, and weekly. The `test` job is a
  matrix over Ubuntu, macOS and Windows running `gofmt`, `go vet`, a
  `CGO_ENABLED=0` build, `go test ./...` and `go test -race ./...`; the other
  jobs lint, generate coverage and send it to Coveralls, fuzz all four targets,
  run the `smbclient` interop suite, and cross-build for `linux/arm64`.
- The macOS and Windows legs are `continue-on-error`, because the server is
  Linux-only and they cannot build yet. They are kept as the signal that
  portability drift has appeared; only the Linux leg gates anything.
- **A release is gated.** `release` runs only on a `v*` tag and needs `lint`,
  `coverage`, `test` and `fuzz`, so it is skipped rather than published when any
  of them fails. It builds both static binaries, smoke-tests `--version` and
  `--check`, refuses a tag that disagrees with `Version` in `doc.go`, runs the
  benchmarks and puts their output at the top of the release description.
- **`golangci-lint`** has a configuration now (`.golangci.yml`, schema v2) and
  the tree passes it at zero findings. Getting there fixed three real findings —
  an allocation in `UTF16LE`, a dead field in `krbStep`, and two unchecked
  `InotifyRmWatch` errors — and restated two deliberate test constructs instead
  of suppressing them.
- **`TestVersionMatchesChangelog`** is new: it pins the newest released
  `CHANGELOG.md` heading to `Version`, the same drift the release job refuses to
  publish.

## [1.4.0] — 2026-10-05

First release of the Go implementation: a complete port of the SMB2/SMB3 server
it is verified against, at that server's 1.4 feature level, with no CGO and no
`unsafe` anywhere in the module.

### Added

- **Protocol**: SMB 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1. NEGOTIATE (with the
  preauth-integrity and encryption negotiate contexts), SESSION_SETUP, LOGOFF,
  TREE_CONNECT/DISCONNECT (with an `IPC$` stub), CREATE (including `RqLs` lease
  contexts), CLOSE, FLUSH, READ, WRITE, QUERY_DIRECTORY (six information
  classes), QUERY_INFO (file, filesystem and a synthesized security descriptor),
  SET_INFO, LOCK, IOCTL (`FSCTL_VALIDATE_NEGOTIATE_INFO`,
  `FSCTL_QUERY_NETWORK_INTERFACE_INFO`), CHANGE_NOTIFY, CANCEL, ECHO, compound
  requests and credit accounting.
- **Authentication**: NTLMv2 against a local user database, Kerberos via
  SPNEGO/GSS with a keytab, and optional guest/anonymous sessions; the `auth`
  key selects which mechanisms are advertised and accepted.
- **Security**: SMB2 HMAC-SHA256 and SMB3 AES-CMAC signing (with
  `require_signing`), SMB 3.1.1 SHA-512 preauth integrity, and SMB3 encryption
  with AES-128/256-GCM and AES-128/256-CCM (`encrypt`, `prefer_aes256`).
- **Caching and notification**: read-caching and handle-caching leases with
  cross-worker break delivery, and inotify-backed directory change notification.
- **Transport**: one `SO_REUSEPORT` listener per worker, a goroutine per
  connection, batched responses per wakeup, and zero-copy reads that move file
  pages to the socket through `splice(2)` at an explicit file offset.
- **Tests**: the full unit and protocol suite, socket-level end-to-end tests
  (pipelining, zero-copy reads at several offsets, IOCTL, change notification, a
  real lease break, framing rejection, the encrypted request path with
  independently derived keys), four native Go fuzz targets, in-repository
  benchmarks, and `bench/interop-smbclient.sh`, which drives the server with
  Samba's `smbclient` across the dialect matrix, file operations,
  authentication and SMB3 encryption.
- **Docs**: a README, project instructions for agents (`AGENTS.md`), and notes
  on architecture, testing, benchmarks, tuning, leases, Kerberos, FIPS 140-3
  mode, concurrency and the port itself, plus a man page.

### Changed relative to the implementation this was ported from

- The io_uring reactor was replaced by Go's networking primitives: `net`
  listeners and goroutines, with the same behavioural contract (one transmit
  stream per connection, batched responses, zero-copy reads, cross-worker break
  delivery). The ring-only configuration keys `sqpoll` and `core_pinning` were
  dropped rather than accepted and ignored.
- Kerberos no longer links a system GSS library; the acceptor is pure Go
  (`jcmturner/gokrb5/v8` for the Kerberos wire protocol).
- AES-CMAC, AES-CCM and MD4 are implemented in this module (Go's standard
  library has none of them) and validated against the RFC test vectors.
- The OpenSSL/FIPS crypto backend has no equivalent here; FIPS 140-3 mode is
  documented in terms of Go's native validated module instead.
- Correctness and hardening fixes found while porting and while testing against
  a real client:
  - sealed responses are appended to the response batch rather than written over
    it, so pipelined encrypted requests are all answered;
  - zero-copy reads use an explicit file offset, so a handle's own position is
    never disturbed (the naive form of the copy walked past EOF after enough
    reads);
  - the rest of a request batch is no longer dropped when one of its frames
    needs a zero-copy reply, which is what made a real client report read
    timeouts;
  - a session that requires encryption refuses requests that arrive unsealed
    instead of serving them in the clear;
  - the NTLMSSP challenge echoes `NEGOTIATE_SEAL` when the client asks for it,
    which is what lets Samba's client enable SMB3 encryption;
  - directory search patterns are matched as DOS wildcards (`?`, `*`,
    case-insensitive) instead of compared for equality, so `ls *.txt`, `del *`
    and the like work from real clients instead of reporting no such file.
  See `docs/PORTING.md` for the full list of divergences.

### Not implemented

Share-level authorization only (no per-user share lists or SID→uid mapping),
write-caching leases, multi-leg Kerberos exchanges, SMB Direct (RDMA), and
intra-connection request concurrency (measured as unnecessary; multichannel is
the scaling path).
