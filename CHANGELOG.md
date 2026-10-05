# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
conventional commits.

## [Unreleased]

### A supported platform set: Linux, macOS, the BSDs and Windows

The server no longer builds on Linux alone. The four facilities pure Go does not
provide — sharing a listening port between workers, watching a directory,
locking a byte range, and moving file bytes to a socket — now live in `pkg/`,
one implementation per mechanism with a **real, documented fallback** where a
platform has nothing sound. Nothing above that layer is platform-dependent, so no
platform gets a weaker protocol: signing, encryption, preauth integrity, the
resource limits and the panic guards are one Go codebase everywhere.

- **`pkg/reuseport`** — `SO_REUSEPORT` on Linux, macOS and the BSDs; on Windows
  it deliberately sets *nothing* and hands the workers a single shared socket,
  because Windows' `SO_REUSEADDR` lets another process take the port over.
- **`pkg/watch`** — inotify on Linux, kqueue on macOS and the BSDs,
  `ReadDirectoryChangesW` on Windows, and a polling watcher where none of those
  exists. The inotify decoder also moved here.
- **A watch is registered before the client is told it is pending.** The
  notifier used to take its instructions on its own goroutine, so the watch could
  be installed *after* the interim `STATUS_PENDING` response had gone out — a
  window in which a client that pended a CHANGE_NOTIFY and immediately changed
  the file lost the change, and the pending operation then never completed at all
  (only a CANCEL or a disconnect could end it). Registration now happens on the
  connection's goroutine, during request processing, which is ordered before the
  response is written. The same change makes completion deterministic for a
  cancel that races an event, and makes `TestServerChangeNotify` deterministic
  instead of relying on the notifier being scheduled in time.
- **`pkg/rangelock`** — an in-process registry that is authoritative for SMB's
  per-handle semantics on every platform, with the kernel's own lock on top where
  the platform has a per-handle kind (OFD locks on Linux, `LockFileEx` on
  Windows). macOS and the BSDs have only process-scoped POSIX locks, which would
  be actively wrong here, so they do not take one.
- **Windows locks are exact-match objects, so its kernel table is rebuilt rather
  than nudged.** A Windows lock can only be released with the range it was taken
  with (no partial unlock, no releasing two adjacent locks at once), and a handle
  may not take a range it already holds (so no in-place upgrade, and no re-locking
  what it holds) — while SMB requires both, and a range past the largest signed
  offset is refused outright. `planMirror` computes, for each change, the region
  affected and therefore exactly which of the handle's objects must be released
  and which ranges taken in their place; it is plain arithmetic over ranges, so it
  is tested on every platform rather than only on Windows. A range is now also
  expressed with a length that cannot overflow, which is what a "to the end of the
  file" lock needs there. A process outside the server that wins a race for a
  range mid-change makes the operation report `LOCK_NOT_GRANTED`, and if the range
  cannot be put back that handle's locks stop being mirrored — counted, and
  reported by `--list-platform`, so the degradation is visible.
- **`pkg/zerocopy`** — `splice(2)` on Linux, `sendfile(2)` on macOS and the
  BSDs, a bounded buffered copy on Windows, plus a fallback to the buffered path
  when a host filters the syscall (a seccomp container) — counted, so the
  downgrade is visible. The sendfile path's accounting is kept apart from the
  syscall (`pumpChunks`) precisely so it can be tested everywhere: macOS and the
  BSDs report a partial send *together with* `EAGAIN`, and a loop that counted
  only the clean successes would desynchronize the offset and hand the client a
  response with duplicate bytes in it. Fatal errors are never counted, because
  their out-length may still hold the count that went in.
- **`pkg/fsutil`** — portable file metadata, timestamps, filesystem sizes and
  read-ahead hints, including the platforms where each is unavailable
  (`statvfs` on NetBSD, `SetFileTime` and `FILE_FS_SIZE_INFORMATION` on Windows,
  and `ErrUnsupported` rather than an invented value in the last resort).
- **Locks are now bounded**: `rangelock.MaxRangesPerHandle` and
  `MaxRangesTotal` cap the ranges one handle, and the server, may hold, since a
  LOCK request carries up to 64 ranges and a client may repeat it. Exceeding
  either answers `STATUS_INSUFFICIENT_RESOURCES`.
- **The lock and timestamp paths changed shape.** A lock's write-access rule is
  enforced from the handle's own record instead of being left to the kernel, so
  Linux, macOS, the BSDs and Windows answer a client the same way; and a lock
  conflict is reported as one error whichever table noticed it.
- **Introspection**: `samba.PlatformFacilities()` and `samba.PlatformName()`, and
  a new `samba --list-platform` that prints the mechanisms the running binary
  got. `--check` reports them next to the capabilities, and the capability
  details for locks, notification and zero-copy reads are now derived from the
  packages instead of hardcoded — so they cannot claim a mechanism the binary
  does not have.
- **CI** now *runs* the platform facilities: `go test ./pkg/...` on macOS and
  Windows (real kqueue, `sendfile`, `LockFileEx`, `ReadDirectoryChangesW`,
  `fstatfs`/`statvfs`, `futimes`), while Linux runs the whole suite. The
  `cross-build` job compiles and vets the module — tests included, which is what
  keeps the suite portable — for the BSDs and other architectures. No leg is
  `continue-on-error` any more: every one is a gate.
- **Documentation**: the README has a platform support table with the mechanism
  per platform and the caveats that follow from it, `AGENTS.md` records the
  "degrade visibly, never silently" rule, and `ROADMAP.md` no longer lists a
  portable build as out of scope — what remains open there is runtime
  verification on the BSDs, which needs a VM runner.

### Dialect floor, and a real encryption guarantee

- **`encrypt = true` was silently unenforced for every dialect below 3.1.1, and
  this was a real bug.** A cipher was only ever chosen for 3.1.1, so a client
  offering 2.0.2, 2.1, **3.0 or 3.0.2** would negotiate, authenticate and then
  exchange **cleartext** on a server that required encryption — an attacker only
  had to offer 3.0.2 to strip it. Verified by negotiation before the fix:
  `SessionFlags 0x0` and a plaintext `ECHO` answered `0x0`. Three changes close
  it:
  - SMB 3.0 and 3.0.2 encryption is implemented (`smb3EncryptionKeys`: label
    `SMB2AESCCM`, contexts `ServerIn ` / `ServerOut`, cipher fixed at
    AES-128-CCM), pinned by vectors computed independently from MS-SMB2 3.1.4.2.
  - Session establishment refuses any session it cannot encrypt, so the setting
    cannot be evaded with an unusual capability set.
  - `SMB2_GLOBAL_CAP_ENCRYPTION` is now echoed to a 3.0/3.0.2 client that asks
    for it, which is what a client-requested (`seal`) mount needs there.
- **`min_dialect`** is new: the oldest dialect to negotiate (`"2.0.2"` through
  `"3.1.1"`). A client offering nothing at or above the floor is refused with
  `STATUS_NOT_SUPPORTED` rather than downgraded, which is what makes it a
  guarantee. It lives in `introspect.go` (the dialect table, its configuration
  spellings and the floor constants) and `config.go` (the key, its validation and
  `Config.DialectFloor`), with `TestDialectsMatchNegotiation` extended to pin the
  spellings to the table NEGOTIATE actually searches.
- **`encrypt = true` and `min_dialect` are now consistent by construction**: the
  first raises the floor to SMB 3.0, and a configuration that pairs it with an
  explicit 2.x `min_dialect` is **rejected at startup** rather than quietly
  resolved, so an operator's explicit setting is never silently overridden.
- **The internet-safety goal is stated explicitly**, in `AGENTS.md`, `README.md`,
  `doc.go` and `SECURITY.md`, and **SMB1 is recorded as never going to be
  implemented**. `SECURITY.md` now spells out what the 2.x dialects cost: no
  encryption, and no downgrade protection.
- `ROADMAP.md` was reordered by priority, grouped by topic, and each remaining
  item now states the consequence of not doing it; the items settled by the last
  few changes (Kerberos, SMB1, non-Linux, CGO) moved into a single decisions
  section instead of sitting in the TODO lists.

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
  here. It runs on every push, on pull requests, and weekly: `test` (Linux: the
  whole suite, the race detector and the platform-mechanism report), `platform`
  (macOS and Windows: the per-platform facility suite, run rather than compiled),
  `lint`, `coverage`, `fuzz`, `interop` and `cross-build` (the module built and
  vetted, tests included, for the BSDs and the other architectures). The
  `continue-on-error` on the non-Linux legs went away with the port — see the
  entry above for what runs where now, and why the BSDs are compile-verified
  only. A `.gitattributes` now stores every text file with LF, which is what keeps
  the formatting gate (`gofmt -l .`, a byte comparison) meaningful on a Windows
  checkout instead of reporting every file in the tree.
- **A release is gated.** `release` runs only on a `v*` tag and needs `lint`,
  `coverage`, `test`, `platform`, `cross-build` and `fuzz`, so it is skipped
  rather than published when any of them fails. It builds both static binaries, smoke-tests `--version` and
  `--check`, refuses a tag that disagrees with `Version` in `doc.go`, runs the
  benchmarks and puts their output at the top of the release description.
- **`golangci-lint`** has a configuration now (`.golangci.yml`, schema v2) and
  the tree passes it at zero findings. Getting there fixed three real findings —
  an allocation in `UTF16LE`, a dead field in `krbStep`, and two unchecked
  `InotifyRmWatch` errors — and restated two deliberate test constructs instead
  of suppressing them. The `InotifyRmWatch` calls now live in `pkg/watch`.
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
