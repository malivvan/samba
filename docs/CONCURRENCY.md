# Concurrency: requests within one connection

**In one line: requests on a single SMB connection are served serially, on
purpose, and measurements say that is not the bottleneck.**

## What the server does

Each connection has one reader goroutine and one driver goroutine. The driver
processes every complete frame it has (up to a batch of 64 or a 1 MiB response
watermark) and writes one response burst. Requests on the same connection are
therefore ordered: a request is not started until the previous response has been
queued.

Two exceptions are deliberate:

- A **zero-copy READ** defers the rest of the batch: buffered responses are
  flushed, then the transfer runs, then the batch continues. The socket ordering
  is preserved, and the transfer itself is a kernel-side copy (or a bounded
  buffered one on Windows), so the driver
  goroutine is not busy copying.
- Filesystem I/O runs **without** the session lock, so a read on one channel of
  a session does not block another channel of the same session on a different
  connection.

## Why not concurrency inside a connection?

Measured, twice, on the implementation this port is verified against:

1. **The linked zero-copy read chain.** Suspicion: single-channel read
   throughput lagged raw TCP because of the round trips between splice-in, the
   header send and splice-out. Submitting them as one linked chain changed
   throughput by ~0%. Conclusion: the single-channel cap is the SMB
   request/response pipelining depth and the network, not server round trips.
2. **Read path is not the bottleneck.** One channel reached roughly the same
   fraction of the raw TCP ceiling regardless of how many requests were in
   flight internally, while four *connections* scaled linearly.

Since the client already pipelines (many outstanding reads per channel) and the
transport is kernel-side, adding intra-connection parallelism would add
ordering complexity, a pipe pool and a response reorder buffer for no measured
gain. The scaling axis that does pay is **connections**, which is why SMB3
multichannel is implemented: one mount, several channels, one core each.

If you want more throughput: enable `multichannel = true` and mount with
`multichannel,max_channels=N`, or use multiple mounts. See
[TUNING.md](TUNING.md).
