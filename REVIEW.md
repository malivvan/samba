# Security & stability review

A review of the whole package with the mindset of an attacker holding a socket:
what can a peer make the server **allocate**, **hold**, **do repeatedly**, or
**crash on**, before and after authentication. Every finding is listed with its
severity, the concrete attack, the fix, and how the fix is verified. Nothing
here is a theoretical nit — each item was turned into code, and most into a test.

Scope: the transport (`server.go`, `zerocopy.go`, `notify.go`), the protocol
layer (`smb2.go`, `handlers.go`, `pattern.go`), the filesystem layer (`vfs.go`),
authentication (`ntlm.go`, `spnego.go`, `auth.go`), crypto (`crypto.go`,
`cmac.go`, `ccm.go`, `md4.go`), state (`session.go`, `lease.go`), configuration
(`config.go`) and the resources they share.

## Summary

| # | Finding | Severity | Status |
|---|---|---|---|
| R-1 | Request buffering per connection was unbounded (heap exhaustion) | High | Fixed |
| R-2 | No limit on concurrent connections (fd/goroutine/memory exhaustion) | High | Fixed |
| R-3 | No limit on sessions, per connection or overall | High | Fixed |
| R-4 | No limit on open handles per session (fd exhaustion for everyone) | High | Fixed |
| R-5 | No limit on tree connects per session | Medium | Fixed |
| R-6 | No limit on pending CHANGE_NOTIFY (kernel inotify watch exhaustion) | Medium | Fixed |
| R-7 | Lease table could grow without bound (handle-caching leases outlive CLOSE) | Medium | Fixed |
| R-8 | A peer could stall forever with an incomplete frame | High | Fixed |
| R-9 | A peer with a zero receive window pinned the response writer | High | Fixed |
| R-10 | The zero-copy pump had no stall detection | High | Fixed |
| R-11 | A per-request warn line let a peer flood the log (disk/CPU) | Medium | Fixed |
| R-12 | The Kerberos keytab was read once per logon (I/O amplification) | Medium | Fixed, then obsolete |
| R-13 | A panic in any connection or worker goroutine killed the process | High | Fixed |
| R-14 | The panic handler itself could panic and kill the process | Medium | Fixed |
| R-15 | `Start` after `Stop` left workers nothing could shut down (`Wait` hung) | Low | Fixed |
| R-16 | `Wait` did not cover connection goroutines | Low | Fixed |
| R-17 | A READ racing a CLOSE on another channel closed the descriptor mid-read | Medium | Fixed |
| R-18 | Testing a directory for emptiness materialised the whole directory | Low | Fixed |
| R-19 | AES-CCM silently truncated an unencodable message length | Low | Fixed |
| R-20 | NTLMSSP token search was O(n·m) over a whole 4 MiB frame | Low | Fixed |
| R-21 | `HandleTable.Len` was left stale by `CloseAll` (the handle cap could be bypassed) | Low | Fixed |
| R-22 | `Server.Addr` raced with `Start` on the listener field | Low | Fixed |
| R-23 | `maxSecurityBlob` was unreachable dead code (false defense) | Info | Removed |
| — | Regression introduced while fixing R-1, caught by the interop suite | — | Fixed |

Two things the review **deliberately did not change**, because they are the
protocol's documented behaviour rather than defects: share-level authorization
with all I/O as the server's Unix user, and following symlinks that already
exist inside a share (`wide links`). Both are recorded in
[SECURITY.md](SECURITY.md) and [ROADMAP.md](ROADMAP.md).

## Findings

### R-1 — Unbounded request buffering per connection (High)

**Attack.** The reader goroutine hands complete frames to the driver over a
64-slot channel. Nothing bounded the *bytes* in that queue, so a peer could send
64 maximum-size frames (4 MiB + headers each, ~275 MiB) and then stop reading
its responses: the driver blocks in its first socket write, the reader keeps
queueing, and the server's heap grows by hundreds of megabytes per connection.
A handful of connections is enough to OOM a small host.

**Fix.** `limits.go` adds a byte `budget` per connection (`maxQueuedRxBytes`,
one maximum frame plus slack). The reader *reserves* the frame's size before it
allocates it and blocks while the reservation does not fit — so the excess stays
in the kernel socket buffer, where the OS already bounds it, instead of in the
heap. `conn.releaseFrame` hands the reservation back as each frame is consumed,
and `budget.Shutdown` releases everything outstanding when the connection tears
down, so a blocked reader can never be left parked.

**Verified.** `TestBudgetAcquireAndRelease`, `TestBudgetAllowsAnOversizedRequestWhenEmpty`,
`TestBudgetGiveUp`, `TestBudgetShutdownReleasesWaiters`, `TestBudgetReleaseIsDefensive`;
end-to-end by `bench/interop-smbclient.sh` (20 MiB upload/download over a real
client).

### R-2 — No limit on concurrent connections (High)

**Attack.** Every accepted connection costs goroutines, buffers and a file
descriptor. An attacker opening connections in a loop exhausts descriptors
(which also breaks the server's own `open(2)` calls and `accept(2)`) or memory.

**Fix.** `max_connections` (default 512, negative = unlimited) is enforced by a
`connLimiter` in the accept path; over the limit the connection is closed
immediately with a logged reason. The limiter is release-balanced: the accept
path holds a deferred release until the connection's own teardown takes over, so
an error or panic in between cannot leak a slot, and an unmatched release cannot
drift the counter negative and open the gate permanently.

**Verified.** `TestConnLimiter` (limit, reuse, unmatched release, unlimited, nil),
`TestServerRefusesBeyondMaxConnections` (a second connection is closed while the
first is served, and the slot is reusable after the first goes away).

### R-3 — No limit on sessions (High)

**Attack.** Sessions are cheap to request and, unlike files, need no share
access: one connection could ask for a session per `SESSION_SETUP` and grow the
server's memory (each session carries a handle table and a tree map) without
bound. A single connection could also drain a global budget and deny service to
everyone else.

**Fix.** Two bounds: `maxSessionsPerConn` (64; multichannel spreads a session
across connections, not the reverse) and a registry-wide `maxSessionsTotal`
(65536). Both answer `STATUS_INSUFFICIENT_RESOURCES`. The per-connection check
runs *before* allocating, so a refused session is never created.

**Verified.** `TestSessionPerConnectionCap`, `TestSessionTotalCap`.

### R-4 — No limit on open handles per session (High)

**Attack.** Each open handle is a file descriptor. A client opening files in a
loop reaches `RLIMIT_NOFILE`, after which *other* clients cannot open their own
files (and the server cannot `accept`). The systemd unit raises the limit, but
that only moves the ceiling; one client can still consume all of it.

**Fix.** `maxHandlesPerSession` (16384, matching Samba's default open-file
limit) answers `STATUS_INSUFFICIENT_RESOURCES`; `HandleTable.Len` provides the
count.

**Verified.** `TestHandleCap` (the cap refuses, and closing a handle makes room
again through the protocol).

### R-5 — No limit on tree connects per session (Medium)

**Attack.** `TREE_CONNECT` is nearly free and allocates a tree entry plus a
monotonically increasing tree id; a loop grows the map (and eventually wraps the
id counter).

**Fix.** `maxTreesPerSession` (4096) answers `STATUS_INSUFFICIENT_RESOURCES`.

**Verified.** `TestTreeConnectCap`.

### R-6 — No limit on pending CHANGE_NOTIFY (Medium)

**Attack.** Each pending notification registers an inotify *watch*, and the
kernel's per-user watch limit is shared with every other process owned by that
user. A client pending notifications in a loop can exhaust it for the whole
host — a denial of service that reaches outside the server.

**Fix.** `maxNotifyWatchesPerConn` (256) answers
`STATUS_INSUFFICIENT_RESOURCES`; a cancelled or closed notification frees its
slot.

**Verified.** `TestNotifyWatchCap` (including that a CANCEL has no response of
its own, completes the pending operation with `STATUS_CANCELLED`, frees the
slot, and that the freed slot is immediately reusable).

### R-7 — Unbounded lease table growth (Medium)

**Attack.** A lease with handle-caching deliberately outlives `CLOSE`, so a
client could open a file with a fresh random lease key, close it, and repeat —
growing the lease table (and the server's memory) without bound while also
holding an unbounded number of `LeaseGrant` records.

**Fix.** `maxLeasesPerFile` (64) and `maxLeasesTotal` (65536) bound the table.
When a grant is refused the open still succeeds and the client simply does not
get to cache (it re-reads), which is the safe direction to fail in; the lease
*key* is still recorded on the handle so a write through it exempts the client's
own key from a break.

**Verified.** `TestLeaseTableCaps` (per-file and total caps, refresh always
allowed, release/break/teardown return credit),
`TestCreateWithoutLeaseWhenTableIsFull` (a full table yields a successful CREATE
with `OPLOCK_NONE`).

### R-8 — A peer could stall forever with an incomplete frame (High)

**Attack.** The reader framed a message as "4-byte length, then that many
bytes". A peer could send the length (or part of the body) and then stop
indefinitely, holding a connection, its goroutines and its reservation forever
— with no timeout, N such connections deny service permanently.

**Fix.** `frameBodyTimeout` (5 minutes, generous for a slow link sending a
multi-megabyte write) arms a read deadline for the *body* only, so an idle
connection is never disconnected while an unfinished frame is reaped.

**Verified.** `TestServerReapsIncompleteFrame` (shortens the timeout, sends a
length plus one byte, and requires the server to close).

### R-9 — A zero-window peer pinned the response writer (High)

**Attack.** Responses are written with a plain blocking `Write`. A peer that
advertises a zero receive window and stops reading parks the connection's driver
goroutine indefinitely — per connection, and with no limit before this review,
in aggregate.

**Fix.** Every response write arms a `stallTimeout` (5 minutes) write deadline
and clears it afterwards. The deadline is re-armed per write, so a client that is
slow but making progress is never disconnected; only a peer that stops moving is
given up on (and dropping it is the only correct action anyway, since the
response stream is already broken).

**Verified.** Covered by the existing socket tests (all writes go through
`conn.write`); `TestServerReapsIncompleteFrame` exercises the same deadline
machinery on the read side.

### R-10 — The zero-copy pump had no stall detection (High)

**Attack.** The splice pump waits for socket writability with a bounded
`poll(2)`, but retried forever: a peer that never reads a large FILE READ keeps
that connection's driver goroutine, its pipe and its (referenced) file
descriptor for as long as it likes.

**Fix.** The pump takes a stall deadline that is *extended by every byte that
moves*, so only a peer that makes no progress is aborted.

**Verified.** `TestSpliceStallTimeout` (a 4 MiB transfer into a socket whose peer
never reads must abort promptly), `TestSpliceTransfersCorrectly` (a 300 KiB
transfer with a reader arrives byte-for-byte), `TestSpliceShortReadReportsError`.

### R-11 — Log flooding (Medium)

**Attack.** Warn-level lines are emitted per event, and several are per request
(a rejected request, a failed logon, an unencrypted frame on a sealed session).
A peer can therefore drive unbounded log output: filling the log filesystem (a
host-level denial of service) and burning CPU in the logging path.

**Fix.** Warn output is rate limited (a 200-line burst, then 50/s), with a
summarising line reporting how many messages the limit swallowed so nothing is
lost silently. Info and debug output are unchanged.

**Verified.** `TestWarnRateLimit` (the burst is allowed, the bucket empties, and
it refills with time).

### R-12 — Kerberos keytab read per logon (Medium) — obsolete

**Attack.** The acceptor — and therefore the keytab parse — was built per
connection (a port of the original design, where a GSS credential was not
`Send`). A client repeating `SESSION_SETUP` made the server re-read and re-parse
the keytab every time: pure I/O and CPU amplification.

**Fix.** The acceptor is built once per server (`Srv.kerberosAcceptor`, guarded
by `sync.Once`) and shared; the keytab and settings are read-only after
construction, and the replay cache is already internally synchronised.
`NewServer` also checks the keytab at startup, so a misconfigured server fails
fast (fatal when `auth = "kerberos"`, a warning when NTLM remains as a fallback).

**Verified.** `TestKerberosAcceptorIsShared` (the same instance is returned, the
error is memoised, and an NTLM-only policy needs no keytab).

**Obsolete.** Kerberos was removed from the server entirely — including the
acceptor, the keytab, the startup check and that test — so there is no keytab to
read and the amplification is gone with the feature. See the authentication note
in [AGENTS.md](AGENTS.md). The finding is left here because it is part of the
record of this review, not because the code it describes still exists.

### R-13 — A panic in a goroutine killed the process (High)

**Attack.** Any reachable panic — a bug in a parser, an unexpected nil, an
unhandled syscall result — propagated out of a connection goroutine and took the
whole process down with it, disconnecting every other client. Go's recovery is
per goroutine and the runtime has no equivalent of a per-request recover, so
without an explicit guard the server had a single point of failure reachable
from the network.

**Fix.** Every long-lived goroutine now runs under a guard that logs the panic
*with a stack trace* and tears down only that connection (or that worker
iteration), so one malformed frame cannot take the server down. The accept loop
recover is per iteration, so a panic while accepting does not end the worker
either, and a panic while delivering a lease break is contained to the worker.

**Verified.** `TestConnGuardRecoversAndCloses` (a panic tears the connection
down and closes its `done` channel; a nested panic is contained; and the
bare-connection case is covered too).

### R-14 — The panic handler could itself panic (Medium)

**Attack.** Found while testing R-13: the recovery path read `c.w.id`, and a
connection without a worker (any hypothetical construction path) turned a
contained panic into an uncontained one — i.e. the safety net had the exact
failure mode it existed to prevent.

**Fix.** The handler is written defensively: it tolerates a missing worker and a
missing `done` channel, and only then logs and shuts down.

**Verified.** `TestConnGuardRecoversAndCloses` includes a `conn` with no worker.

### R-15 — `Start` after `Stop` hung `Wait` (Low)

**Attack.** Not remotely reachable, but a lifecycle mistake: starting a stopped
server bound fresh listeners that nothing would ever close, so `Wait` blocked
forever (a hung shutdown, and hung tests).

**Fix.** `Start` reports an error once the server has been stopped.

**Verified.** `TestServerStopIsIdempotent`.

### R-16 — `Wait` did not cover connection goroutines (Low)

**Fix.** The server's `WaitGroup` now covers connection goroutines as well, so
`Stop(); Wait()` means every connection has finished tearing down (which also
makes leak checks meaningful). The `Add` happens while the accept goroutine
still holds its own count, so it cannot race `Wait`.

**Verified.** `TestServerStopIsIdempotent` asserts the connection count is zero
after `Wait`.

### R-17 — READ racing CLOSE closed the descriptor mid-read (Medium)

**Attack.** Reads deliberately run *without* the session lock so channels of one
session can read in parallel. `CLOSE` on another channel took the lock, removed
the handle and closed the descriptor — so a read in flight could find its
descriptor closed underneath it. For a buffered read the client saw a spurious
error; for a zero-copy read the header had already promised bytes, so the
connection was dropped. (The original implementation avoided this by `dup`-ing
the descriptor per read; this port used positional I/O without a dup, which
regressed the guarantee.)

**Fix.** `OpenFile` carries a reference count: `use()` (called under the session
lock, so it cannot race `close`) hands out the file, and the transport or the
buffered path calls `release()` when it is done. `close()` marks the handle dead
and defers the actual `Close` until the last reference goes, guarded by a
`sync.Once`. Zero-copy plans carry their handle via `ZcReadPlan.Owner` and
release it on every path, including an abandoned plan when the connection is
torn down first. `File` is never cleared any more, so a reader that already
copied the pointer can never see a torn value.

**Verified.** `TestOpenFileReferenceCounting` (a descriptor stays usable under an
outstanding reference, `use` after `close` is refused, the last release closes
it, double release/close is idempotent).

### R-18 — Emptiness test materialised a directory (Low)

**Attack.** `SET_INFO` on a directory (delete-on-close flag) read the entire
directory listing into memory just to answer "is it empty?" — an authenticated
client with write access could point that at a huge directory and force a large
allocation.

**Fix.** Ask for exactly one name (`Readdirnames(1)`).

**Verified.** Exercised by the protocol tests for delete-on-close; behaviour is
unchanged (still `STATUS_DIRECTORY_NOT_EMPTY` for a non-empty directory).

### R-19 — AES-CCM length-field truncation (Low)

**Attack.** CCM encodes the message length in `L` octets; a message longer than
`2^(8L)` would have been encoded with the high bits dropped, authenticating a
different length than the data. Unreachable for SMB3 (whose payloads are bounded
by the frame size, and whose `L` is 4), but a primitive should not pretend to
seal what it cannot encode.

**Fix.** `ccmSeal` returns an error instead.

**Verified.** `TestSMB3CCMParameters` and the RFC 3610 vector tests.

### R-20 — O(n·m) token search over a whole frame (Low)

**Attack.** `findToken` scanned for the 8-byte NTLMSSP signature byte by byte.
A client could send a 4 MiB garbage SESSION_SETUP blob repeatedly and make the
server do ~32M comparisons per request — a CPU denial of service that costs the
attacker only bandwidth.

**Fix.** Use the standard library's optimised `bytes.Index` (and the frame
ceiling, plus the u16 length field, already bound the blob to 64 KiB).

**Verified.** `TestClassifyRawAndWrapped`, `TestNTLMNegotiateFlags`, and the
`FuzzNTLM` target.

### R-21 — `HandleTable.Len` was stale after `CloseAll` (Low)

**Attack.** `Len` is `len(slots) - len(free)`, which is correct while handles are
inserted and removed one at a time — but `CloseAll` (session teardown) closed
every handle and cleared the slots without returning them to the free list, so
`Len` kept reporting the old count. The per-session handle cap (R-4) is enforced
from `Len`, so a session whose handles had been bulk-closed would have refused
new opens.

**Fix.** `CloseAll` resets the table (slots, generations and free list), which
also guarantees that every id handed out before the reset misses cleanly.

**Verified.** `TestHandleTableCloseAll` (Len is zero afterwards, every
descriptor is closed, and the call is idempotent).

### R-22 — `Server.Addr` raced with `Start` (Low)

**Attack.** `Start` assigns the worker's listener field and `Addr` reads it, from
different goroutines and with no synchronization, so a caller polling `Addr`
while the server starts is a data race — the kind of thing that is harmless
until it is not.

**Fix.** The listener is published and read through locked accessors
(`setListener`/`listener`); `Addr`, `Stop` and the accept loop all use them.

**Verified.** The race detector caught this while the new coverage tests were
written; `go test -race ./...` is clean.

### R-23 — Dead defence removed (Info)

The review added a `maxSecurityBlob` bound on SESSION_SETUP security buffers,
then found it unreachable: the length field is a `uint16`, so a blob can never
exceed 64 KiB in the first place. It was removed rather than kept as
defence-theatre that inflates the code and its coverage numbers. The same review
tightened `isHex` to reject the empty string (harmless today, since the caller
checks the length first, but a validator should not call `""` valid hex).

## Regression found and fixed during this work

While implementing the per-connection budget (R-1) the give-up predicate was
inverted, so the reader gave up whenever a frame did not fit *immediately*
instead of waiting: a client pipelining two large writes had its connection
dropped mid-transfer. The unit tests passed (the budget's own semantics were
consistent) and only the real-client interop suite caught it —
`cli_push returned NT_STATUS_CONNECTION_DISCONNECTED`. Fixed by making
`budget.Acquire(n, giveUp)` abort only when `giveUp()` reports that the caller is
closing, and the failure is now covered by the budget tests as well as by
`bench/interop-smbclient.sh`. This is recorded here deliberately: it is exactly
the class of bug that a unit-only review would have shipped.

## Tests added with the fixes

Every finding above is covered by a test, and the review also added tests for the
parts of the server that had none: every command and its parameter validation
(`commands_test.go`), every decoder's error path (a truncation sweep in
`malformed_test.go`), the session-setup policy and multichannel binding paths
(`auth_test.go`; that list included a complete Kerberos login built from a real
keytab, since removed with the feature), the notifier and its inotify parsing
(`notify_test.go`), the
resource limits (`limits_test.go`, `caps_test.go`), the reconnect/panic/timeout
paths (`hardening_test.go`) and the CLI (`cmd/main_test.go`).

Package statement coverage went from 68% to **94%** while doing so, which is a
side effect rather than the goal: the tests were written to assert behaviour a
client depends on (statuses, byte layouts, error classification), not to touch
lines.

## Reviewed, no change required

These were examined closely and are safe as they stand; they are listed so the
review's coverage is visible.

- **Wire decoding.** Every parser reads through the bounds-checked `Reader` or
  `sliceAt`, so a truncated or hostile frame yields a protocol error rather than
  a panic. The compound loop, negotiate-context walk, lease-context chain and
  the DER reader all provably terminate (each step consumes at least a header).
  The four fuzz targets cover these paths.
- **Session and handle identification.** A session id is validated against
  `pc.Channels` for *this* connection, so guessing another connection's session
  id is refused; `FileId`s are generation-tagged, so a stale or guessed id misses
  cleanly instead of aliasing a new handle.
- **Credits.** The grant is clamped to a 512-credit window and the charge is
  floored at 1, so a client cannot inflate its window.
- **Cryptography.** MAC comparisons are constant time; per-channel keys are
  derived from the session key and the channel's preauth hash, so nonce counters
  are never shared across channels; the transform header's AAD covers the nonce,
  length, flags and session id.
- **Path handling.** `..` and NUL are rejected, the share path is the jail, and
  inode/size data comes from the server's own `stat`.
- **Arithmetic.** Offsets and lengths are `uint64`/`uint32` from the wire; the
  kernel rejects out-of-range values (`EINVAL`/`EOVERFLOW`) and those map to a
  protocol error. Negative conversions are caught by the same layer rather than
  by unchecked arithmetic in Go.
- **Log content.** Client-supplied strings (user, share, path) are logged with
  `%q` where they reach the log, so a peer cannot forge log lines.
- **Descriptor reuse.** Handles are `*os.File`s that Go marks closed, so a
  closed handle can never be dereferenced into a different file (the failure
  mode a raw fd table would have).
- **Configuration.** Unknown keys are rejected, shares are validated at load,
  and a guard test loads the shipped example.
- **Short-but-sufficient request bodies.** The handlers read the fixed fields
  they need and ignore the rest of a request body, so a body that is shorter
  than the structure defined by MS-SMB2 is still served if it carries every
  field used. This matches the implementation this port was verified against and
  every real client (which always send the full fixed part); a body too short to
  hold even the used fields is answered with `STATUS_INVALID_PARAMETER`, which
  `TestMalformedCommandsAreAnswered` verifies for every command at every
  truncation length.
