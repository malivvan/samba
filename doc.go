// Package samba is a from-scratch SMB2/SMB3 file server.
//
// It speaks SMB 2.0.2 through 3.1.1 with NTLMv2 and Kerberos (GSS-API/SPNEGO)
// authentication, SMB2/3 signing, SMB 3.1.1 preauth integrity, SMB3
// multichannel, and SMB3 encryption (AES-128/256-GCM and AES-128/256-CCM). It
// supports a user database, optional guest access, byte-range locks, leases
// (read-caching and handle-caching), and directory change notification.
//
// The package is written entirely in pure Go: no CGO and no unsafe, so it is
// statically linkable and memory safe.
//
// # Architecture
//
// A single process serves all shares. main resolves the TOML configuration into
// a shared Srv context and starts N workers, each owning its own SO_REUSEPORT
// listener; the kernel spreads accepted connections across them. Every
// connection is handled by two goroutines: a reader that frames inbound NetBIOS
// session messages, and a driver that processes them in batches, writes the
// batched responses, and interleaves server-initiated frames (lease breaks and
// CHANGE_NOTIFY completions) queued from other goroutines.
//
// Large unsigned READs bypass userspace: the response header is written and the
// file's cached pages are then streamed straight to the socket, which the Go
// runtime performs with the kernel's splice machinery.
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
// feature set the server implements: SMB 2.0.2–3.1.1, NTLMv2 + Kerberos,
// signing, preauth integrity, multichannel, encryption and leases.
const Version = "1.4.0"
