# Security Policy

samba is a network file server — it parses untrusted input from the network — so
security reports are taken seriously.

## Reporting a vulnerability

**Please do not open public issues for security vulnerabilities.**

Report privately through GitHub Security Advisories ("Security" tab → "Report
a vulnerability") on <https://github.com/malivvan/samba>. Include steps to
reproduce, affected versions, and impact. Expect an acknowledgement within a
few days.

## Goal: safe to expose to the internet

**It is an explicit goal of this package to be a file server you can put on the
public internet without that being a bad idea.** That ambition shapes the
defaults and the scope:

- Nothing is accepted from a peer that the server cannot bound — every
  client-controllable resource has a limit, every parse is bounds-checked, and a
  panic drops one connection rather than the process.
- Weaknesses that exist only for compatibility are refused rather than
  tolerated. **SMB1 will never be supported** (see below), and Kerberos was
  removed rather than shipped with the RC4-HMAC fallback real deployments still
  rely on (see [AGENTS.md](AGENTS.md)).
- A security-relevant setting is a guarantee, not a hint: `encrypt = true`
  refuses a client it cannot encrypt rather than quietly serving it in the
  clear, and `min_dialect` refuses a weaker dialect rather than downgrading.

This is an objective, not a claim. **No external security review has been done**
— that is the largest outstanding item in [ROADMAP.md](ROADMAP.md). Until it
is, treat the goal as the direction of travel and keep the mitigations below in
place.

## Dialects, and what the old ones cost you

SMB 2.0.2 and 2.1 are the weakest thing this server speaks, and they are weak in
two specific ways worth stating plainly:

- **They have no encryption.** SMB3 encryption arrived with dialect 3.0. There
  is no mechanism in 2.x for it, so a 2.x session is cleartext on the wire no
  matter how the server is configured.
- **They have no downgrade protection.** SMB 3.1.1's preauth integrity is what
  binds the negotiation to the session; 2.x has nothing equivalent, so an
  attacker positioned on the path can influence which dialect and which
  capabilities are chosen.

Consequences for an untrusted network:

- `require_signing = true` is the minimum for 2.x: it at least detects
  modification. It does not give you confidentiality.
- `min_dialect = "3.0"` drops 2.x entirely, and with it both problems. A client
  offering only a dialect below the floor is refused (`STATUS_NOT_SUPPORTED`),
  never quietly downgraded.
- `encrypt = true` implies `min_dialect = "3.0"` for exactly that reason — 2.x
  cannot satisfy it — and a configuration that sets `encrypt = true` alongside a
  2.x `min_dialect` is rejected at startup as a contradiction rather than
  silently resolved. It is also enforced per session: a session the server
  cannot encrypt (no cipher was negotiated) is refused, so the setting cannot be
  bypassed by offering an unusual capability set.

**SMB1 is never going to be implemented.** It is not merely legacy: it is a
protocol whose useful portion is a long list of historical vulnerabilities, and
every client that matters has spoken SMB2 or SMB3 for years. Today an SMB1
NEGOTIATE gets the SMB2 wildcard response, so an SMB1-only client times out
rather than being served; the roadmap item is to refuse it explicitly.
## Current security posture (1.4)

The server is at 1.4: it has real authentication, signing and encryption, but no
external security review has been done yet. Know the following before deploying.

- **Written in pure Go.** No CGO and no `unsafe`, anywhere in the module
  (verified by CI). The binary is static, and every wire parser runs under the
  Go memory-safety guarantees rather than hand-managed buffers.
- **SMB3 encryption** — AES-128-GCM, AES-256-GCM, and AES-128/256-CCM (SMB
  3.1.1; 3.0 and 3.0.2 fix AES-128-CCM). Set `encrypt = true` to require it, or
  let clients request it (`seal`); `prefer_aes256` selects AES-256 when offered.
  `encrypt = true` also implies `min_dialect = "3.0"` and refuses any session it
  cannot encrypt — see the dialect section above. Without encryption,
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
- **Deployment** — the goal is a server that is safe to put on the public
  internet, but a full security review has not been done, so read that as the
  direction of travel rather than a warranty. For anything beyond a trusted LAN,
  at minimum: `require_signing = true`, `encrypt = true` (which implies
  `min_dialect = "3.0"`), `allow_guest = false`, and a dedicated unprivileged
  user that owns only the share trees.

## Supported versions

Only the latest tagged release receives fixes.
