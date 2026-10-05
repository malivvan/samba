# Roadmap

samba is at feature parity with the implementation it was ported from, at that
implementation's 1.4 level. This is what is deliberately *not* done yet, in
rough priority order. Everything here is a known limitation with a stated
reason, not an oversight — [SECURITY.md](SECURITY.md) and
[docs/PORTING.md](docs/PORTING.md) have the details.

## Next

1. **Per-share authorization.** Today any authenticated user can use every
   share, `read_only` applies to everyone, and all I/O runs as the server's Unix
   user. Next step: per-share user/group lists, then a SID→uid/gid mapping so
   on-disk permissions distinguish clients. Until then, run the server as a
   dedicated unprivileged user owning only the share trees.
2. **Lease breaks on every conflicting change.** Read-caching leases are broken
   on WRITE. Truncate, overwrite-by-open, rename and unlink should break them
   too, and write-caching leases — which need a break *with acknowledgement* so
   the client can flush dirty data — are never granted at all.
3. **An external security review.** The server parses untrusted network input
   for a living. The fuzz targets cover the pre-auth parsers; a review of the
   whole surface is still outstanding, so port 445 should not face the public
   internet.

## Later

4. **Multi-leg Kerberos.** The acceptor handles the single-leg AP-REQ exchange
   that cifs.ko and Windows perform and rejects multi-leg exchanges with a log
   line. Supporting them needs per-channel acceptor-context persistence.
5. **SMB Direct (RDMA).** Designed but not implemented, and it needs hardware
   plus a userspace HCA path that Go cannot reach without CGO — see
   [docs/SMBDIRECT.md](docs/SMBDIRECT.md). The practical alternative today is
   multichannel over a jumbo-frame, multiqueue fabric.
6. **SMB1 refusal.** An SMB1-only client currently gets the SMB2 wildcard
   response and hangs until it times out instead of being told no.
7. **Registered buffers / zero-copy for encrypted reads.** Encrypted payloads
   must be sealed, so they take the buffered path. Zero-copy for those would
   need sealed framing that the kernel can still splice from.
8. **A test/container image.** The host suites in `bench/` need root and
   cifs.ko. A container that runs a real client against the server would let the
   integration tests run in CI.

## Not planned

- **A portable (non-Linux) build.** The transport and the filesystem layer rely
  on Linux facilities by design (`SO_REUSEPORT`, `inotify`, OFD locks,
  `splice`).
- **CGO, `unsafe`, or a C crypto backend.** The whole point of this
  implementation is a statically linkable, memory-safe server; FIPS mode comes
  from Go's own validated module instead (see [docs/FIPS.md](docs/FIPS.md)).
