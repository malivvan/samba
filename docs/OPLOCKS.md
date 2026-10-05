# Leases and oplocks

A lease lets a client cache a file it has open: read its content locally, and
sometimes even keep the cache after closing the file. The server's job is to
grant the safe subset and to *break* a lease when somebody else needs
conflicting access, so no client is ever left with a stale cache.

## What this server grants

Only the safe subset is granted, and only when `oplocks = true` (the default):

| Requested | Granted | Why |
|---|---|---|
| Read-caching (`R`) | yes | Distinct clients' read leases coexist; there is no dirty data to lose. |
| Read + handle-caching (`R`/`RH`) | yes, if asked | Handle-caching lets the lease survive CLOSE, so the client does not have to re-open and re-read. |
| Write-caching (`W`) | **never** | A write-caching lease has to be broken *with acknowledgement*, so the client can flush dirty data first. That path is not implemented, so it is never promised. |
| Any lease on a directory | no | Only file caching is granted. |
| Any lease on an encrypted session | no | A break notification on an encrypted session would have to be sealed itself; not implemented, so leases are not offered where the break could not be delivered. |

Leases are offered only when the client negotiates SMB 2.1 or newer (the
`CAP_LEASING` capability) and requests one through the `RqLs` create context.
`RequestedOplockLevel = 0xFF` in a CREATE marks "a lease is requested"; the
granted state is echoed back in an `RqLs` create-context response, and the
CREATE response carries `OPLOCK_LEASE` as its granted oplock level.

## When a lease breaks

Read-caching has no dirty data, so breaking it to `none` is fire-and-forget:
there is nothing for the client to flush and no acknowledgement to wait for.
A break is raised when another open writes the same file:

```
client A: open file, request R (or RH)  ──► granted, cached
client B: open + WRITE the same file    ──► A's lease is broken first, then the write
client A: receives an OPLOCK_BREAK notification for its lease key
```

The order matters: the conflicted leases are broken *after* the write has hit
the file, so a client that re-reads on the break sees the final content rather
than racing a partial write. The writing handle's own lease key is exempt, so a
client that owns a lease and writes through it does not break itself.

A break notification (MS-SMB2 2.2.23.2) is a server-initiated response with
`MessageId = -1` carrying the 16-byte lease key, the current state and the new
state. It is signed when the session signs. Because a read-caching → none break
needs no acknowledgement, `Flags` is 0.

## Cross-worker delivery

Two opens of the same file can be served by different workers, so a write on
worker B may need to break a lease held by a connection owned by worker A. A
connection object belongs to its own goroutines and cannot be written to from
outside, so the break travels:

```
WRITE handler (worker B)        LeaseTable.BreakConflicts() → []BreakMsg
                                Mailbox[wid_A].Post(msg)     (MPSC queue + wake)
worker A mailbox goroutine      drain, look up the slot by (index, generation)
                                push onto that connection's deferred queue
connection A driver goroutine   build + write OPLOCK_BREAK (the only writer)
```

The generation check is what makes a stale break safe: if the connection slot
was recycled, the break is dropped instead of being delivered to an unrelated
client. If a connection disappears without a clean CLOSE, `ReleaseConn` drops
every lease it held, so grants cannot leak.

## Configuration

```toml
oplocks = true    # default; set false to never grant a lease
```

Turning leases off is safe and costs a round trip per re-open; it is the right
choice if a client is known to cache badly.

## Verifying

Unit tests cover the table semantics (`lease_test.go`: grant/refresh, break only
the other keys, unleased writers break everything, connection teardown releases
its grants). The socket-level test `TestServerLeaseBreak` runs the whole path:
two clients, one holding an `R`/`RH` lease, the other writing the file, and the
holder must receive the break with its lease key and the state transition.
