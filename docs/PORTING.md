# Porting notes: how this code maps onto the implementation it is verified against

This package is a Go port of a mature SMB2/SMB3 server originally written in
Rust. The goal was **feature parity**, expressed idiomatically in Go, with the
whole thing free of CGO and `unsafe`. This document is the honest record: what
maps onto what, what is deliberately different, and which inherited behaviours
were kept as-is rather than "fixed".

## Module map

| Original module | This package | Notes |
|---|---|---|
| `src/wire.rs` | `wire.go` | `Reader`/`Writer` replace the `Rdr`/`Put` pair; both stay bounds-checked |
| `src/status.rs` | `status.go` | NTSTATUS constants and the errno mapping |
| `src/log.rs` | `log.go` | Same three levels and `[level] message` format |
| `src/crypto.rs` + `crypto_rustcrypto.rs` | `crypto.go`, `cmac.go`, `ccm.go`, `md4.go` | One pure-Go backend instead of a pluggable one |
| `src/config.rs` | `config.go` | TOML; the same keys minus two (below) |
| `src/session.rs` | `session.go` | Session + per-session handle table behind a per-session mutex |
| `src/lease.rs` | `lease.go` | Same table semantics; the eventfd mailbox becomes an MPSC queue with a wake channel |
| `src/vfs.rs` | `vfs.go` | Handle table and metadata mapping; handles wrap `*os.File` |
| `src/net.rs` | `netinfo.go` | Interface enumeration and `NETWORK_INTERFACE_INFO` encoding |
| `src/ntlm.rs` | `ntlm.go` | NTLMv2 + the NTLM-specific SPNEGO helpers |
| `src/spnego.rs` | `spnego.go` | DER writer/reader, mechanism selection, `NegTokenInit2` hint |
| `src/krb5.rs` | — | Kerberos was ported, then removed: see "Kerberos was removed" below |
| `src/smb2/mod.rs` | `smb2.go` | Header codec, compound dispatch, transform header, `ProcessFrame` |
| `src/smb2/handlers.rs` | `handlers.go` | Every command handler |
| `src/uring.rs` | `server.go`, `notify.go`, `zerocopy.go` | The transport, rewritten (below) |
| `src/main.rs` | `cmd/main.go` | Same core flags (`--config`, `--check`, `--version`), plus `--dump-config`, `--list-dialects`, `--list-ciphers`, `--list-interfaces` and `--log-level`/`--listen`/`--workers` overrides |
| `src/lib.rs` | `doc.go` | Package documentation and the version constant |
| `fuzz/fuzz_targets/*` | `fuzz_test.go` | cargo-fuzz → native Go fuzzing (four targets) |
| `bench/*` | `bench/*` | The same host scripts, adapted to this binary |
| `CLAUDE.md` | `AGENTS.md` | Project context for agents and contributors |
| `docs/*` | `docs/*` | Migrated and rewritten where the design changed |

## The transport is the one real rewrite

The original is io_uring end-to-end: one ring per worker thread, a
completion-driven state machine per connection, `splice` chains for reads,
`send_zc` for large buffered writes, multishot accept, SQPOLL, core pinning.

io_uring has no idiomatic Go equivalent — using it would mean raw ring syscalls
fighting the runtime's own poller. The transport is therefore written in Go's
terms while preserving every *behavioural* property that matters:

| Behaviour | Original | This package |
|---|---|---|
| N workers, kernel-balanced accepts | one `SO_REUSEPORT` listener per ring | one `SO_REUSEPORT` listener per worker goroutine |
| One transmit stream per connection | completion-driven state machine | one driver goroutine (the only writer) |
| Batched responses per wakeup | all complete frames in the rx buffer, 1 MiB watermark | `processBatch`: up to 64 frames or the 1 MiB watermark |
| Zero-copy read | `splice(file→pipe)` → `send(hdr, MSG_MORE)` → `splice(pipe→socket)` | header write → `splice(file→pipe)` → `splice(pipe→socket)`, all with an explicit file offset |
| Buffered send for signed/encrypted | `send`/`send_zc` | `Write` |
| `send_zc` for large buffered sends | `IORING_OP_SEND_ZC` | not ported: Go has no userspace `MSG_ZEROCOPY` path, and the copy it saves is the one covered by the splice read path |
| Multishot accept, SQPOLL, core pinning | ring features / `sched_setaffinity` | accept loop; the two ring-only knobs were dropped (below) |
| Cross-worker lease breaks | per-worker eventfd polled in the ring | per-worker mailbox goroutine + each connection's deferred queue |
| CHANGE_NOTIFY | inotify fd read registered in the ring | inotify fd wrapped in `*os.File`, read by a watcher goroutine (the runtime poller parks it) |

Two configuration keys disappeared with the ring: `sqpoll` and `core_pinning`.
Neither has a Go equivalent worth faking (the runtime scheduler owns thread
placement), so they are **gone rather than silently ignored** — a config that
sets them now fails to load with a clear "unknown key" error. Everything else
in the config format is unchanged, including the TOML key names.

## Authentication and crypto without CGO

- **NTLM** is unchanged in behaviour: NTLMv2 verification, the RC4 key exchange,
  the SPNEGO wrappers. MD4 (the NT hash), HMAC-MD5 and RC4 come from
  `md4.go` (hand-written, RFC 1320 vectors) plus Go's `crypto/md5` and
  `crypto/rc4`.
- **Kerberos was removed.** It was first ported (pure Go, no system GSS library),
  and then deleted outright, along with the `jcmturner/gokrb5` dependency: this
  server is aimed mainly at non-corporate users and at being reachable from the
  internet, and real Kerberos deployments still lean on RC4-HMAC (etype 23),
  which has known weaknesses. The reasoning is recorded in
  [AGENTS.md](../AGENTS.md), and what replaced the shared half of it is
  `auth.go` — session establishment, which NTLM uses and any future mechanism
  would too.
- **AES-CMAC and AES-CCM** are implemented here because Go's standard library
  has neither. Both are validated against the RFC's own test vectors
  (RFC 4493 §6, RFC 3610 §8) and exercised by the fuzz targets. AES-GCM and the
  SHA-2 family come from the standard library.
- **No OpenSSL/FIPS backend.** The original could route the FIPS-relevant
  primitives through system OpenSSL; that would require CGO. Instead the
  documented FIPS story is Go's native FIPS 140-3 module
  (`GOFIPS140`/`GODEBUG=fips140=on`) — see [FIPS.md](FIPS.md), which is explicit
  about what is and is not covered.

## Tests

Every unit test in the original has a counterpart here, plus socket-level tests
the original did not have:

- the cryptographic vectors (RFC 1320, RFC 4231, RFC 4493, RFC 3610, NIST GCM,
  the NT-hash and RC4 known answers) are asserted byte for byte;
- the three big protocol tests — a full session, NTLMv2 with signing
  enforcement, and SMB 3.1.1 preauth chaining with an independently recomputed
  signing key — are ports of the originals, driving `ProcessFrame` the same way;
- the lease-request parser, the interface-info encoder, path resolution, the
  handle table, the lease table and the mailbox are covered as before;
- `server_test.go` adds what the original only tested through `bench/`: real
  sockets, real pipelining, the zero-copy read path at several offsets, a
  CHANGE_NOTIFY completed by a real inotify event, a lease break delivered to a
  second client, and rejection of a desynchronized stream;
- the two cargo-fuzz targets became four native Go fuzz targets (the SPNEGO
  classifier and the lease-context walker were added because they are the same
  kind of attacker-facing parser).

## Deliberate divergences

Everything below is a conscious change, not an accident of translation.

1. **Encrypted responses are appended, not written over the batch.** In the
   original, re-encrypting a sealed response cleared the connection's response
   buffer, which could throw away responses already batched from earlier frames
   in the same wakeup. This port appends the sealed frame to the buffer, so the
   batch is preserved and the multi-frame encrypted case is correct.
2. **Zero-copy reads use an explicit file offset.** The obvious Go spelling of
   "send this file's contents to the socket" uses, and advances, the file
   descriptor's position. SMB reads are offset-addressed and one handle can be
   read concurrently from several channels, so that is wrong here; `zerocopy.go`
   passes the offset to `splice(2)` instead. (This was caught by a benchmark
   reading past EOF after enough iterations — see TESTING.md.)
3. **A dropped connection releases more than its leases.** The original
   released the connection's lease grants on teardown but left its session
   channels counted, so handles opened on an abruptly closed connection could
   linger. Here, teardown also drops the connection's channels and, when the
   last channel goes, the session and its handles.
4. **The NEGOTIATE SPNEGO hint advertises NTLMSSP only.** The original could
   advertise a Kerberos-preferred list; this server has one mechanism, so the
   hint names exactly that one. Offering a mechanism the server would then
   refuse only produces a failed logon.
5. **`ProcessFrame` reports a "close the connection" outcome explicitly.** The
   original signalled it through a `FrameAction::Close` variant; the Go version
   returns an action value, with the same trigger (an undecryptable encrypted
   frame, or one that arrived with no key for its session).
6. **Positional I/O instead of `dup`.** The original duplicated a handle's file
   descriptor for each read so that the slow path ran without the session lock.
   Here the handle is an `*os.File` and reads use `ReadAt`, which is
   position-independent, so no duplication is needed and concurrent reads on
   different channels are safe by construction.
7. **An encryption-required session refuses unsealed requests.** The server
   advertises `SESSION_FLAG_ENCRYPT_DATA` to tell a client to seal, and the
   original then processed a plaintext request anyway. Here, once a session
   requires encryption (`encrypt = true`) or a client has started sealing, a
   request that arrives unsealed is answered with `STATUS_ACCESS_DENIED`
   instead of being served in the clear — otherwise an attacker could strip
   sealing from the session, which is exactly what SMB3 encryption is for. A
   request that arrived inside a transform header is exempt (it *is* sealed),
   as are NEGOTIATE, SESSION_SETUP and CANCEL.
8. **The NTLMSSP challenge echoes `NEGOTIATE_SEAL` when the client asks for
   it.** The original's fixed challenge flags omitted the bit, which makes
   Samba's client refuse to turn on encryption at all
   (`HRES_SEC_E_UNSUPPORTED_FUNCTION` during SPNEGO login). Echoing a capability
   the client requested does not weaken anything — SMB3 encryption is activated
   by the SMB-layer negotiation, not by this flag — and it is what makes
   `smbclient --client-protection=encrypt` work.
9. **Directory search patterns are matched as patterns.** `QUERY_DIRECTORY`
   carries a search pattern that the *server* is expected to apply, and the
   original compared it to each entry for equality. That answers
   `STATUS_NO_SUCH_FILE` for every realistic wildcard query — `smbclient`'s
   `ls *.txt`, Explorer filtering, `del *` — so `pattern.go` implements DOS
   wildcard matching (`?`, `*`, case-insensitive, with `*` crossing the dot and
   an insignificant trailing dot) instead. Exact-name queries behave as before.
10. **Small things**: `statusFromErr(nil)` is success; `MaxReadSize` is the
   1 MiB target directly rather than a value probed from the pipe ceiling (the
   pipe is sized opportunistically instead); the pipe wait uses a bounded
   `poll(2)` timeout so a stalled peer cannot delay shutdown.

## Inherited quirks kept on purpose

- **`FSCTL_VALIDATE_NEGOTIATE_INFO`** replies with
  `Capabilities | Guid | SecurityMode | Dialect`, while MS-SMB2 describes the
  last field as a dialect *count* followed by the dialects. This is byte-for-byte
  what the original sends, and it is accepted by cifs.ko and Windows, so it was
  left alone rather than silently changed under clients that already work.
- **SMB1 clients get the 0x02FF wildcard** and are not refused, so an SMB1-only
  client hangs until it times out. Same behaviour, same caveat.
- **Authorization is share-level only**, all I/O runs as the server's Unix user,
  and symlinks inside a share are followed even outside it — as in the original
  and as in Samba's `wide links`.
- **Kerberos is gone**: the original handled a single-leg AP-REQ exchange; this
  server refuses a Kerberos token with `STATUS_NOT_SUPPORTED`.

## Not migrated

The original repository also carried release engineering and distro submission
material (distribution packaging plans, a Fedora/Debian submission write-up,
and a changelog of the Rust project's releases). Those describe that project's
history and processes rather than this server, so they are not part of this
package. What is kept: the licence, the security policy, the architecture,
benchmark, testing, tuning, lease and FIPS notes and the man page, all rewritten
for this implementation.
