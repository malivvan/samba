// Package samba is a from-scratch SMB2/SMB3 file server.
//
// It speaks SMB 2.0.2 through 3.1.1 with NTLMv2 authentication, SMB2/3 signing,
// SMB 3.1.1 preauth integrity, SMB3 multichannel, and SMB3 encryption
// (AES-128/256-GCM and AES-128/256-CCM, negotiated from 3.1.1 and fixed at
// AES-128-CCM in 3.0/3.0.2). It supports a user database, optional guest
// access, byte-range locks, leases (read-caching and handle-caching), and
// directory change notification.
//
// The package is written entirely in pure Go: no CGO and no unsafe, so it is
// statically linkable and memory safe.
//
// # Security goal
//
// The goal is a file server that can be exposed to the public internet without
// putting the host at risk, and the defaults and scope follow from that: every
// client-controllable resource is bounded, every wire parse is bounds-checked,
// and a weakness that exists only for compatibility is refused rather than
// tolerated. Two decisions in particular are deliberate and permanent — SMB1 is
// not supported and will not be, and Kerberos was removed rather than shipped
// with the RC4-HMAC fallback (see AGENTS.md) — and two settings are guarantees
// rather than hints: `min_dialect` refuses a weaker dialect instead of
// downgrading to it, and `encrypt = true` refuses any session the server cannot
// encrypt instead of serving it in the clear.
//
// No external security review has been done yet; SECURITY.md and ROADMAP.md are
// explicit about what that does and does not imply.
//
// # Architecture
//
// A single process serves all shares. main resolves the TOML configuration into
// a shared Srv context and starts N workers, each accepting independently from a
// shared listening socket (or from its own, where the platform has SO_REUSEPORT,
// in which case the kernel balances the connections). Every connection is
// handled by two goroutines: a reader that frames inbound NetBIOS session
// messages, and a driver that processes them in batches, writes the batched
// responses, and interleaves server-initiated frames (lease breaks and
// CHANGE_NOTIFY completions) queued from other goroutines.
//
// Large unsigned READs avoid a userspace copy where the platform allows it: the
// response header is written and the file's cached pages are then streamed
// straight to the socket — splice(2) on Linux, sendfile(2) on macOS and the
// BSDs, a bounded buffered copy on Windows.
//
// # Platforms
//
// Linux, macOS, FreeBSD, OpenBSD, NetBSD, DragonFly BSD and Windows are
// supported. The four facilities Go does not provide — a shared listening port,
// directory watching, byte-range locks and file-to-socket copies — live in the
// pkg/ subpackages, one implementation per mechanism and a documented fallback
// for the rest: nothing above that layer is platform-dependent, and no platform
// gets a weaker protocol. PlatformFacilities and PlatformName report which
// mechanism a build actually got, and the README's support table is the map,
// including the caveats (a lock not enforced against local processes on macOS
// and the BSDs, a directory watcher that cannot name the entry that changed on
// kqueue).
//
// # Library surface
//
// The protocol, configuration and transport layers are exported so they can be
// fuzzed, benchmarked, embedded and reused:
//
//   - ProcessFrame is the wire entry point: framed bytes in, response bytes (or
//     a zero-copy read plan) out. It is what the fuzz targets drive.
//   - BuildReadRespPrefix, BuildReadErr, BuildLeaseBreak and BuildNotifyFinal
//     build the server-initiated frames.
//   - EnumerateInterfaces and EncodeInterfaceInfo produce the multichannel
//     interface advertisement.
//   - LoadConfig, ParseConfig and Config expose the TOML configuration model.
//   - NewServer, Server.Start, Server.Stop and Server.Addr run the server, and
//     Version reports the implemented feature level.
//
// See README.md for the configuration reference and docs/ for the design,
// testing, tuning and benchmark notes.
package samba

// Version is the released feature level of the server. It tracks the SMB
// feature set the server implements: SMB 2.0.2–3.1.1, NTLMv2, signing, preauth
// integrity, multichannel, encryption and leases.
const Version = "1.4.0"
