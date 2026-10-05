# SMB Direct (RDMA) — design sketch, not implemented

SMB Direct would let a client move file data over RDMA between registered
memory regions, bypassing the kernel TCP stack. It is on the roadmap and is
**not implemented**: there is no `FSCTL_QUERY_RDMA_CAPABILITIES` handling, no
RDMA transport, and the interface advertisement never sets the RDMA capability
bit (it advertises RSS only).

Reaching feature parity with the rest of the stack requires hardware: two hosts
with RDMA-capable NICs (iWARP or RoCEv2) on the same fabric. The design below is
kept so the work can be picked up deliberately rather than rediscovered.

## What the protocol needs

1. **A second transport.** Direct TCP stays for negotiation; SMB Direct opens
   RDMA connections and advertises `SMB2_GLOBAL_CAP_RDMA` plus the `fsctl`
   capabilities. This is a new listener and a new connection type.
2. **Memory registration.** Every buffer a client reads from or writes to must
   be registered with the HCA and advertised as a buffer descriptor, so the
   zero-copy path becomes a scatter/gather list rather than a pipe.
3. **Credit and message framing per connection**, because RDMA sends are
   posted and completed asynchronously rather than written to a stream.
4. **Fallback.** Not every client negotiates RDMA, and this server must keep
   working over TCP for all of them.

## Why it does not fit the current Go transport

The existing transport is deliberately plain `net` (`SO_REUSEPORT` listeners,
goroutine per direction, splice for the bulk transfer). RDMA needs a userspace
HCA library — which, in Go, means either CGO (forbidden here) or a native
in-kernel interface that Go does not expose. A real implementation would have to
be a separate, build-tagged transport behind the same protocol layer
(`ProcessFrame` is transport-agnostic by design, so the protocol side is ready).

Practical guidance today: use multichannel over a fast fabric with jumbo frames
and multiqueue (see [TUNING.md](TUNING.md)) — that is the reachable path to
saturating a 100 GbE link without RDMA.
