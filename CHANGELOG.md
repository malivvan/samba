# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
conventional commits.

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
  real lease break, framing rejection), four native Go fuzz targets, and
  in-repository benchmarks.
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
- Two correctness fixes: sealed responses are appended to the response batch
  rather than written over it, and zero-copy reads use an explicit file offset so
  a handle's own position is never disturbed. See `docs/PORTING.md` for the full
  list of divergences.

### Not implemented

Share-level authorization only (no per-user share lists or SID→uid mapping),
write-caching leases, multi-leg Kerberos exchanges, SMB Direct (RDMA), and
intra-connection request concurrency (measured as unnecessary; multichannel is
the scaling path).
