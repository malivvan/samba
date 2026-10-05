# Architecture

samba is a from-scratch SMB2/SMB3 server written in pure Go. This document
describes the design as implemented; `AGENTS.md` has the file map, and
[PORTING.md](PORTING.md) records how the structure maps onto the Rust
implementation it was ported from and verified against.

## Process model

```
main
 ├─ load TOML config, resolve the shared context (users, shares, GUID,
 │  interfaces, session registry, lease table, per-worker break mailboxes)
 └─ start N workers (default: one per CPU core)
     each worker:
       own listening socket, or a shared one where the platform cannot bind the
       address more than once (SO_REUSEPORT → the kernel balances the accepts)
       own accept loop goroutine
       own break-mailbox goroutine
       a table of connections, slot-indexed and generation-tagged
```

A connection is served by goroutines that are started by the worker and never
touch another connection's state:

- **reader** — reads NetBIOS-framed messages and hands complete frames to the
  driver over a buffered channel. It never decodes SMB2.
- **driver** — the only writer to the socket. It processes frames in batches,
  writes the batched responses, serves zero-copy read plans, and drains the
  deferred queue.
- **notifier** — owns the connection's directory watcher and its watches, and
  translates the platform's change events into queued CHANGE_NOTIFY
  completions. Registration is *not* on this goroutine: the connection's own
  goroutine registers the watch while it processes the request, because the
  interim `STATUS_PENDING` response is written after processing — so the
  directory is being watched before the client is told the operation is pending,
  and a client that pends a notification and immediately changes the file cannot
  miss the change. The notifier goroutine only consumes events, and it never
  writes to the socket.

Workers share three things through the immutable-ish `Srv` context:

- the configuration, share table and interfaces (read-only after startup);
- the **session registry** (`session.go`), a mutex-protected map of sessions,
  each with its **own** mutex and its own open-handle table — this is what makes
  SMB3 multichannel work, because channels on different workers bind to the same
  session and share its trees and handles;
- the **lease table** (`lease.go`), keyed by `(share index, inode)`, plus a
  per-worker **break mailbox**: an MPSC queue with a wake channel, so a WRITE on
  worker B can deliver a lease break to a connection owned by worker A.

File I/O never runs while the session lock is held for the duration of the
operation: the driver looks the handle up under the lock, then reads or writes
positionally, so reads on different channels do not serialize. Commands that
mutate the handle table or the trees take the session lock for the operation.

## Connection lifecycle

**accept** — the accept loop hands each connection a recycled or fresh slot.
Slots carry a generation that is bumped when recycled, so a lease break aimed at
a dead connection is dropped instead of delivered to whoever now owns the slot.

**framing** — inbound bytes are read as `[4-byte NetBIOS length][message]`. A
non-zero first byte means the stream is desynchronized (only NetBIOS session
messages are legal on direct TCP 445) and the connection is dropped. Frames
larger than `MaxTransact + slack` are refused the same way.

**batching** — when the driver wakes with at least one frame, it drains up to 64
more that are already waiting and processes them all before writing, so a
pipelined client stream (cifs issues long runs of WRITEs) is answered in one
pass and one socket write instead of one round trip per request. It stops early
when the accumulated response reaches a 1 MiB watermark, or when a request needs
a zero-copy reply.

**server-initiated frames** — lease breaks and CHANGE_NOTIFY completions can
originate on other goroutines or other workers. They are appended to the
connection's *deferred queue* (unbounded, mutex-protected, with a wake channel)
and written by the driver, before the next batch. This preserves the invariant
that a socket has exactly one writer, and it means a break is delivered as soon
as the transmit side is free — not while a response batch is mid-flight.

**bounds and timeouts** — nothing a peer can drive is unbounded, and no wait is
eternal. The reader *reserves* a frame's memory from a per-connection byte budget
before allocating it, so a peer that stops reading its responses cannot make the
server buffer more than one maximum-size frame; a connection slot is reserved
before the connection is served, so a connection flood is refused rather than
served badly. A frame that is announced but not finished within
`frameBodyTimeout` is reaped, a response write that makes no progress for
`stallTimeout` aborts, and the zero-copy pump gives up on a peer that stops
moving data. An *idle* connection is deliberately never disconnected, because a
mounted share sitting unused is normal. The quantities are in `limits.go`, each
with the attack it prevents, and the reasoning is in [REVIEW.md](../REVIEW.md).

**panic isolation** — every long-lived goroutine runs under a guard: a panic is
logged with its stack trace and tears down that connection (or that worker
iteration) only. A file server must not have a single point of failure reachable
from a frame.

**teardown** — when the reader ends (peer closed, framing error, read error) the
driver flushes nothing more, releases every lease held by the connection's
slot, drops its session channels (tearing a session down when its last channel
goes, closing that session's remaining handles), hands back its memory
reservation and connection slot, and recycles the slot.

## The platform layer (`pkg/`)

Four things the server needs are the operating system's, not Go's: sharing a
listening port between workers, watching a directory for changes, locking a byte
range, and moving file bytes to a socket. Each lives in its own package under
`pkg/`, with one implementation per mechanism and a real fallback for the
platforms that have none:

| Package | Interface the rest of the server sees | Mechanisms |
|---|---|---|
| `pkg/reuseport` | `Listeners(n, network, addr)` → the sockets the workers share | `SO_REUSEPORT`, or one shared socket |
| `pkg/watch` | `Add`/`Remove`/`Events`: one ID per watched directory, batched notifications | inotify, kqueue, ReadDirectoryChangesW, polling |
| `pkg/rangelock` | `Lock(f, off, len, kind, writeAccess)` | the in-process registry, plus OFD locks or `LockFileEx` where they exist ⁽*⁾ |
| `pkg/zerocopy` | `Send(conn, file, off, n, stall)` | `splice(2)`, `sendfile(2)`, buffered copy |
| `pkg/fsutil` | file metadata, timestamps, filesystem sizes, open flags | the platform's own calls, or `ErrUnsupported` |

⁽*⁾ The registry is authoritative for what an SMB client may lock, on every
platform, because SMB's semantics (a range is split by a partial unlock, merged
with its neighbours, converted in place, and never conflicts with itself) are
POSIX's, not every kernel's. Where a kernel offers per-handle locks the same change
is *also* applied to it, so a local process sees it too — but the two tables are
not always updated the same way. Linux's OFD locks take the change directly;
Windows' are exact-match objects that can neither be unlocked in part nor taken
twice by one handle, so `planMirror` computes the affected region and the platform
layer releases and re-takes the objects in it. That arithmetic is portable and
tested everywhere; only the two syscalls are per-platform.

The boundary is drawn deliberately: **nothing above this layer knows which
platform it is on.** There are no build tags outside `pkg/`, the protocol code
has one implementation everywhere, and the only platform-dependent values that
reach the surface are the ones `introspect.go` publishes (`PlatformFacilities`,
`PlatformName`), which the CLI prints. That is what keeps a platform from
silently getting a weaker protocol: signing, encryption and preauth integrity
cannot regress per platform, because there is nothing per-platform about them.

The layer also decides *what the host can enforce*. Locks are authoritative in
the server's own registry, so SMB clients always see conflicts; the kernel's own
lock is taken on top where it exists, which is what makes a lock visible to a
local process on Linux and Windows but not on macOS and the BSDs. Directory
notifications carry the changed entry's name where the mechanism reports one
(inotify, ReadDirectoryChangesW, polling) and the "re-enumerate" answer where it
cannot (kqueue). Both differences are in the README support table.

## Zero-copy READ path

A standalone (non-compound) READ of at least 8 KiB whose response does not need
to be signed or encrypted does not copy the file's bytes through the server's own
memory where the platform allows it. The mechanism is the platform's
([pkg/zerocopy](../pkg/zerocopy), see the README support table): on Linux

```
1. write the SMB2 response header
2. splice(file → pipe, at an explicit offset)   ┐
3. splice(pipe → socket)                        ┘ repeated until done
```

on macOS and the BSDs the same two steps are one `sendfile(2)`, and on Windows
the bytes go through a bounded buffer because `TransmitFile` cannot take an
explicit offset. All three satisfy the same contract, which is what the caller
sees and what `pkg/zerocopy`'s tests enforce on every platform.

Two details are load-bearing:

- **A plan holds a reference to its handle.** Reads run without the session
  lock so channels can read in parallel, which means a CLOSE on another channel
  must not close the descriptor mid-transfer: the plan carries a reference
  (`ZcReadPlan.Owner`) that the transport releases on every path, whether the
  plan is served or abandoned.
- **The file is read at an explicit offset.** `sendfile(2)` and the splice
  variant that Go's `io.Copy` reaches for use, and advance, a file descriptor's
  own position. That is unusable here: SMB reads are addressed by offset, and
  one handle can be read concurrently from several channels of a session, so
  every path in `pkg/zerocopy` passes an explicit offset (or reads positionally)
  and none of them touches the descriptor's position. See
  [PORTING.md](PORTING.md) for the bug this replaced.
- **Waiting for the socket is bounded.** The socket is non-blocking; when it is
  full the kernel paths poll for writability with a short timeout and re-check
  whether the connection is shutting down, and the buffered path uses a write
  deadline, so a stalled peer cannot wedge teardown. Every path gives up after
  the same stall budget, and reports it the same way.

The pipe is sized to the advertised `MaxReadSize` where the kernel allows it, so
one read usually moves in a single splice. A kernel that cannot do the transfer
at all — a seccomp filter that blocks `splice(2)`, a host out of descriptors for
the pipe — falls back to the buffered copy rather than failing the read, and
counts it, so `--list-platform` can show that the fast path is not being taken. The response header is written
*before* the payload, which is only sound because the byte count is known up
front: the header is built from the requested length, clamped to the file size
(everything past EOF is an `STATUS_END_OF_FILE` error response *instead of* a
short payload). If a transfer still comes up short — the file shrank under us —
the connection is dropped, because the header has already promised bytes that
will never arrive.

READs inside compound requests, below 8 KiB, or on signed/encrypted sessions
take a buffered positional-read path: the payload has to be hashed or sealed, so
it cannot bypass userspace.

## SMB2 layer

The protocol layer is separated from I/O: `ProcessFrame(srv, connState, frame,
tx)` is a pure function from bytes to bytes plus filesystem side effects, which
is why the whole protocol surface is unit-testable and fuzzable without sockets
or synchronization. The transport only knows about framing and the
`ZcReadPlan` escape hatch.

- **Compounds**: chained requests share a `Chain` (session/tree/previous
  FileId for related operations); responses are 8-byte aligned with
  `NextCommand` patched.
- **SESSION_SETUP is a dispatcher**: `classifyBlob` identifies the security blob
  (SPNEGO NegTokenInit/Resp, a raw GSS token, raw NTLMSSP) and routes it by
  mechanism. NTLMv2 is the only mechanism: it verifies against the `[[user]]`
  database or accepts guest when allowed, and a Kerberos token is refused.
  Either way the resulting session key feeds the SP800-108 KDF for signing and
  encryption keys, and the session itself is established by `auth.go`, which
  every mechanism shares.
- **Signing**: HMAC-SHA256 (2.x) / AES-CMAC (3.x) verify-and-sign; authenticated
  sessions always sign their responses, including the final SESSION_SETUP.
  `require_signing` rejects unsigned requests.
- **Encryption**: `TRANSFORM_HEADER` with AES-128/256-GCM/CCM; inbound frames are
  decrypted before dispatch and outbound responses are sealed. An encrypted
  response is not separately signed — the AEAD tag is the integrity.
- **Credits**: each request's charge is consumed and the grant is
  `clamp(requested, 1, 512 − outstanding)`, a 512-credit window per connection.
- **Dialects** 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1. 3.1.1 negotiates its cipher in
  a negotiate context and carries SHA-512 preauth integrity; 3.0 and 3.0.2 have
  no cipher context and use AES-128-CCM, with the keys derived without a preauth
  hash (`channelEncryption` picks the right family, so session establishment and
  channel binding cannot disagree). The server takes the newest dialect the
  client offers that is at or above `min_dialect` — which `encrypt = true` raises
  to 3.0, because 2.x has no encryption — and refuses a client below the floor
  rather than downgrading to it. An SMB1 NEGOTIATE gets the 0x02FF wildcard
  response whatever dialects it offers; an SMB1-only client cannot parse that and
  times out instead of being refused.

## VFS layer

- Path resolution rejects `..` and NUL bytes; the share path is the jail
  boundary, but symlinks that already exist inside a share are followed, as in
  Samba's `wide links`.
- Open handles live in a generation-tagged slab per session (shared by that
  session's channels). FileIds never repeat across a close, so a stale client
  FileId misses cleanly instead of aliasing a new handle.
- Directory enumeration snapshots the listing at the first QUERY_DIRECTORY and
  serves slices from it; `RESTART_SCANS`/`REOPEN` re-snapshot.
- Byte-range locks use open-file-description locks, so the per-handle semantics
  match SMB (two handles on one file do not conflict with themselves).

## Limits and known compatibility warts

- **One transmit stream per connection**: a zero-copy read serializes behind the
  current response batch. Concurrent reads within one connection were designed
  and then shelved after measurement showed the server was not the bottleneck
  ([CONCURRENCY.md](CONCURRENCY.md)); multichannel is the scaling path.
- **`IPC$`** tree connects get a stub tree (no named pipes, no RPC); DFS
  referrals are unsupported.
- **No SMB Direct** ([SMBDIRECT.md](SMBDIRECT.md)), no registered buffers, and
  no HTTP health endpoint.
- **Kerberos is not implemented at all**: a Kerberos token is refused with
  `STATUS_NOT_SUPPORTED` rather than downgraded to a guest session. See the
  authentication note in [AGENTS.md](../AGENTS.md).
- **No external security review yet**; see [SECURITY.md](../SECURITY.md).
