# Security Policy

samba is a network file server — it parses untrusted input from the network — so
security reports are taken seriously.

## Reporting a vulnerability

**Please do not open public issues for security vulnerabilities.**

Report privately through GitHub Security Advisories ("Security" tab → "Report
a vulnerability") on <https://github.com/malivvan/samba>. Include steps to
reproduce, affected versions, and impact. Expect an acknowledgement within a
few days.

## Current security posture (1.4)

The server is at 1.4: it has real authentication, signing and encryption, but no
external security review has been done yet. Know the following before deploying.

- **Written in pure Go.** No CGO and no `unsafe`, anywhere in the module
  (verified by CI). The binary is static, and every wire parser runs under the
  Go memory-safety guarantees rather than hand-managed buffers.
- **SMB3 encryption** — AES-128-GCM, AES-256-GCM, and AES-128/256-CCM (SMB
  3.1.1). Set `encrypt = true` to require it, or let clients request it
  (`seal`); `prefer_aes256` selects AES-256 when offered. Without encryption,
  data is signed (when negotiated) but cleartext on the wire — prefer
  `encrypt = true` on untrusted networks.
- **Signing** — SMB2 HMAC-SHA256 and SMB3 AES-CMAC; SMB 3.1.1 preauth integrity
  (SHA-512). `require_signing = true` enforces it.
- **Authentication** — **NTLMv2 only**: checked against a local user database,
  with optional guest/anonymous sessions when `allow_guest` is set. Kerberos was
  removed deliberately, along with its dependency — see the note in
  [AGENTS.md](AGENTS.md) (mainly non-corporate users, and not shipping the
  RC4-HMAC fallback that real Kerberos deployments lean on). A Kerberos token is
  refused with `STATUS_NOT_SUPPORTED`, never downgraded to a guest session.
  There is no account lockout.
- **Authorization is share-level only** — `read_only` per share applies to
  everyone. Any authenticated user (or guest, if allowed) can use every share,
  and all file I/O runs as the server process's Unix user, so on-disk
  permissions do not distinguish clients. Run the server as a dedicated
  unprivileged user that owns only the share trees.
- **Crypto** — Go's standard library for AES, HMAC, SHA-2, MD5 and RC4; AES-CMAC,
  AES-CCM and MD4 are implemented in this module (see `cmac.go`, `ccm.go`,
  `md4.go`) and validated against the RFC test vectors. Build with
  `GOFIPS140=latest` (Go 1.24+) to route the standard primitives through Go's
  FIPS 140-3 validated module; see docs/FIPS.md for what that does and does not
  cover.
- **Wire parsers are fuzzed** — the SMB2 frame entry point, the NTLMSSP token
  parser, the SPNEGO classifier and the lease-context walker have native Go
  fuzz targets run in CI (per-push smoke + weekly). Not a guarantee, but the
  attack surface is no longer unexercised.
- **Path safety** — `..` traversal and NUL bytes in client paths are rejected.
  Symlinks that already exist inside a share are **followed, even if they point
  outside it** (like Samba's `wide links`). Clients cannot create symlinks over
  SMB, so only someone with local access to the share tree can plant one.
- **Resource limits** — every client-controllable resource is bounded
  (connections, sessions, handles, inotify watches, leases, buffered request
  bytes) and every stall is timed out, so a single peer cannot exhaust a shared
  resource or hold one forever. A peer that trips a bug cannot take the process
  down either: each connection and worker runs under a panic guard that logs the
  stack and drops only that connection. The limits, the timeouts and the
  reasoning behind each are in [REVIEW.md](REVIEW.md).
- **Deployment** — a hardened build (NTLMv2 + `require_signing`, optionally
  `encrypt`) is reasonable beyond a trusted LAN, but a full security review has
  not been done; do not expose port 445 to the public internet until it has.

## Supported versions

Only the latest tagged release receives fixes.
