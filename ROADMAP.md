# Roadmap

samba is a pure-Go SMB2/SMB3 file server whose goal is to be **safe to expose to
the public internet** (see [AGENTS.md](AGENTS.md) and [SECURITY.md](SECURITY.md)).
This is what is deliberately *not* done yet, in priority order.

**How to read this.** Every item is a known limitation with a stated reason, not
an oversight. Each one says what is missing and what it costs you today, because
"not implemented" only means something if you can tell whether it affects you.
Spec references (`§5`, `§11.4`, …) point into
[docs/SAMBA.md](docs/SAMBA.md), the consolidated specification this server is
written against.

Scope, because it decides what belongs here: this is an **SMB 2.0.2–3.1.1 file
server**, not a re-implementation of the Samba 3 suite. Items that would make it
a different program are in *Settled* below rather than in the TODO lists.

## Settled: decisions, not gaps

Things that are **not** pending work. They are here so they stop being
re-proposed, and so the TODO lists below stay honest about what is actually
open.

- **SMB1 — never.** Not "later": no. SMB1's useful surface is a catalogue of
  historical vulnerabilities, and every client that matters has spoken SMB2/3
  for years. Today an SMB1 NEGOTIATE gets the SMB2 wildcard so an SMB1-only
  client times out; refusing it explicitly is a real (small) item, and it is in
  P0 below. See [SECURITY.md](SECURITY.md).
- **Kerberos — removed.** Deleted along with the `jcmturner/gokrb5` dependency.
  The reasoning (mainly non-corporate users, and not shipping the RC4-HMAC
  fallback that real Kerberos deployments lean on) is in
  [AGENTS.md](AGENTS.md). Bringing it back would be an exported `Authenticator`
  interface, not a re-vendored acceptor — and that interface is deliberately not
  designed yet.
- **A portable (non-Linux) build — no.** The transport and filesystem layer rely
  on Linux facilities by design (`SO_REUSEPORT`, `inotify`, OFD locks,
  `splice`).
- **CGO, `unsafe`, or a C crypto backend — no.** The point of this
  implementation is a statically linkable, memory-safe server; FIPS mode comes
  from Go's own validated module instead (see [docs/FIPS.md](docs/FIPS.md)).
- **A different kind of server.** `passdb`, `idmap`/`winbindd`, NT4 domain
  controller functionality, print services, and the `net`/`pdbedit`/`smbpasswd`/
  SWAT administration tools would each turn this into something other than an
  SMB2/3 file server. They are out of scope as a group; the parts of the spec
  that would make them possible (DCE/RPC named pipes, identity mapping) are
  tracked below only where they also serve a *file-serving* need. Concretely,
  these spec sections are unclaimed rather than pending:
  - **`security = share`** (§13.1.1) and **`security = server`** (§13.1.3) —
    both deprecated in the spec, the second for man-in-the-middle exposure.
  - **`security = domain`** (§13.1.4) and **`security = ads`** (§13.1.5): NT4
    and AD domain authentication. With Kerberos removed and no LDAP, this server
    is local-accounts-only, which is the intended audience.
  - **`passdb backend`** and its backends (§13.2): `tdbsam`, `ldapsam`,
    `ldapsam_compat`, `mysql`, `xmlsam`, `guest`. The static `[[user]]` list is
    the intended model.
  - **NetBIOS name and datagram service** (UDP 137/138) and **SWAT** (TCP 901,
    §21.1): a name/browse daemon and a web admin interface are different
    services, and this one deliberately has no HTTP listener.

---

## P0 — Correctness and assurance for what already ships

### Authorization

1. **Per-share authorization.** Today authentication is per-session and
   authorization is per-share `read_only` for *everyone*: any authenticated
   (or guest) user can use every share, and all I/O runs as the server's Unix
   user. Without per-share user/group lists, a share you meant to keep private
   is only as private as your least-trusted credential, and on-disk permissions
   cannot distinguish clients.

### Caching correctness

2. **Lease breaks on every conflicting change.** Read-caching leases are broken
   on WRITE only. Without breaking them on truncate, overwrite-by-open, rename
   and unlink, a client can keep serving stale cached data after another client
   has changed the file — silent corruption from the client's point of view.
   Write-caching leases, which need a break *with acknowledgement* so the client
   can flush dirty data, are never granted at all; they are what would make
   write performance competitive with Samba.

### Assurance

3. **An external security review.** The server parses untrusted input for a
   living, and the goal is internet exposure. Fuzzing covers the pre-auth
   parsers, but until someone outside the project reviews the whole surface, the
   internet-safety goal stays a direction of travel rather than a claim anyone
   else has checked.

### Hardening

4. **Refuse SMB1 explicitly.** An SMB1-only client (some BMCs, some embedded
   devices) gets the SMB2 wildcard response and hangs until it times out (~20 s)
   instead of being told no. Without it, a misconfigured client presents as a
   mysterious hang rather than an immediate, diagnosable refusal.

---

## P1 — Hardening for an internet-facing deployment

### Transport and negotiation

- **Per-share encryption** (§8.2). The spec allows encryption globally *or per
  share*; today `encrypt` is server-wide only. Without it, a server that must
  encrypt one sensitive share has to encrypt every mount, including the ones
  where a client would rather not pay for it.
- **Downgrade-protection ordering** (§20.3). We pick a dialect by our own
  preference order rather than by following the client's explicit ordering.
  Without it, the negotiation is influenced by us in a way the spec's
  downgrade-protection guidance does not endorse; 3.1.1 preauth integrity covers
  tampering with the exchange, not our choice within it.
- **Session and encryption key rotation on reauthentication** (§20.2). The spec
  requires proper derivation *and rotation*; today a reauthentication keeps the
  original keys. Without it, a long-lived session's keys live for as long as the
  session does, which is exactly what rotation exists to bound.
- **SMB over QUIC** (§5.4, §9.4, §21.1): UDP 443 with the ALPN identifier `smb`.
  Without it, clients that are only permitted SMB over QUIC (a common
  remote-access posture) cannot reach this server at all.
- **SMB2 RDMA transport** ([MS-SMBD], §5.3, §9.3). Needs RDMA hardware and a
  userspace HCA path Go cannot reach without CGO — see
  [docs/SMBDIRECT.md](docs/SMBDIRECT.md). Without it, the practical ceiling is
  multichannel over a jumbo-frame, multiqueue fabric, which is a fraction of
  RDMA's throughput at high core counts.
- **`TRANSPORT_CAPABILITIES`** (§6.3). Advertises the transports (including
  RDMA) a client may reconnect over. Without it, a client cannot be told that a
  better transport exists, so it never tries one.
- **Client-side negotiate validation** (§20.3), if a client role is ever added.
  The server side (`FSCTL_VALIDATE_NEGOTIATE_INFO`) is implemented; a client
  would need to validate the negotiate response it receives, and without it a
  client trusting an unvalidated response is open to exactly the downgrade this
  file exists to prevent.

### Signing and cipher negotiation

- **AES-GMAC signing for 3.1.1** (§8.1, §9.4), and the
  **`SIGNING_CAPABILITIES`** context (§6.3) that negotiates it. We always derive
  AES-CMAC. Without it, a client that insists on AES-GMAC has no algorithm in
  common, and in FIPS-conscious deployments AES-GMAC is often the preferred one.
- **Cipher negotiation beyond AES-128/256-GCM and CCM** (§9.4). We honour the
  client's order (or `prefer_aes256`), but new cipher ids in the spec are
  refused rather than considered. Without it, a future client defaulting to a
  newer cipher gets no cipher at all from this server.
- **Honour the negotiate-context preference ordering** (§6.3) the client sends,
  rather than taking the first cipher we support. Without it, a client's stated
  preference is ignored, which is at best surprising and at worst a downgrade it
  did not ask for.

### Operations

- **Log to a file**, with `log file` (`%m` substitution), `max log size` and
  rotation, and the spec's 0–10 verbosity scale. Today it is three levels to
  stderr. Without file logging, a deployment needs an external supervisor to
  keep logs, and there is no built-in bound on log growth.
- **`deadtime`**: an idle-connection timeout in minutes (0 = never). This server
  deliberately never disconnects an idle connection; exposing the knob makes
  that policy explicit and lets an operator trade memory for connection
  longevity. Without it, a fleet of idle clients holds its share of the
  connection budget forever, with no way to reclaim it short of a restart.

---

## P2 — Completing SMB 2.0.2–3.1.1

### Transport (§5)

- **NetBIOS over TCP on port 139** (RFC 1001/1002), which dialects 2.0.2–3.0.2
  are specified to allow (§5.2). Today only direct TCP 445 is served. Without
  it, clients configured for port 139 cannot connect — and unlike SMB1, 139 is
  still enabled by default on plenty of Windows installs.

### Negotiation and message framing (§6.1, §6.3, Appendix A/B)

- **SMB3 compression**: the `COMPRESSION_CAPABILITIES` context (0x0003) and
  compression itself (algorithm negotiation, compressed data, the compression
  `FSCTL`). Not implemented at all. Without it, a client that compresses gets no
  benefit and falls back to uncompressed transfers, which matters most on the
  slow links where compression is requested.
- **`NETNAME_NEGOTIATE_CONTEXT`** (0x0004), which carries the server's NetName
  for cluster/multichannel identification. Without it, multichannel clients
  cannot match channels to the same server by name.
- **`SMB2_IMPL_ID`** context (0xF100), reporting the implementation
  name/version/GUID. Without it, clients and tooling cannot tell which server
  implementation they reached, which is what makes interoperability triage slow.
- **`SMB2_FLAGS_PRIORITY_MASK`** (0x0070): accept and account for the priority
  field instead of ignoring it. Without it, a client's expressed I/O priority has
  no effect on scheduling here.
- **`SMB2_FLAGS_DFS_OPERATIONS`** (0x10000000): reject DFS operations explicitly
  with a clear status instead of treating them as ordinary requests. Without it,
  a DFS request gets a confusing ordinary answer rather than an honest refusal.
- **`SMB2_KEEPALIVE`** (0x000D, Appendix A): the spec's name for the opcode this
  server implements as ECHO. Same wire format and empty reply, but the keepalive
  semantics (and the "no response required" reading some clients take) are not
  confirmed. Without confirming it, a client that sends KEEPALIVE and expects no
  reply gets one, which is harmless — but unverified.

### Handles, durability and reconnection (§9)

- **Durable handles** (SMB 2.0.2, §9.1): the `DHnQ`/`DH2Q`/`DHnC` create
  contexts, handle reconnection after a network outage, and TREE_CONNECT on a
  reconnected handle. Without them, a brief network blip costs the client its
  open files, which applications see as I/O errors rather than a pause.
- **Resilient handles** (SMB 2.1, §9.2) and **persistent handles** (SMB 3.0 /
  cluster, §9.3). Without them, reclaiming a handle after reconnection is
  impossible, which is the same failure as above on a scale-out deployment.
- **Dynamic reauthentication** (SMB 2.1, §9.2): a session-renewing SESSION_SETUP
  on an established session, including re-deriving keys. Today reauthentication
  is acknowledged without renewing anything. Without it, a session cannot
  outlive its original credential's lifetime.
- **Scale-out / cluster features** (SMB 3.0, §9.3): cluster reconnect contexts
  and `CLUSTER_RECONNECT` handling. Without them, no client can treat this as a
  cluster node, so a failover is a disconnection.

### Namespace, filesystem and compatibility extensions (§11.3, §15)

- **DFS referrals** (`GET_DFS_REFERRAL`, the DFS flag, referral responses). Today
  a DFS request is treated as an ordinary one. Without referrals, a namespace
  that spans shares cannot be traversed: the client is told the path does not
  exist instead of being pointed at the right server.
- **POSIX/UNIX extensions**: symlink creation and reading, hard links,
  chmod/chown, and the UNIX information levels. (UTF-16LE on the wire and 64-bit
  offsets are already implemented.) Without them, a Unix client cannot preserve
  permissions or symlinks through the share — they silently degrade to whatever
  the server's own user can do.
- **Alternate data streams** (§15.2 `streams_depot`): named streams on the wire
  (`file:stream` syntax), and `FileStreamInformation` for more than the default
  `::$DATA`. Without them, applications that store metadata in streams (Office
  documents, `Zone.Identifier`) either lose it or fail on copy.
- **A stackable VFS layer** with per-share module configuration (`vfs objects`),
  where each operation can be intercepted; the Go equivalent of a `.so` module
  is a compile-time plugin registered per share (§15.1, §15.3). Without it, every
  per-share behaviour has to be built into the core server, so
  auditing/recycle/shadow-copy style features cannot be added without forking.
- **The named VFS modules** (§15.2): `default_quota`, `extd_audit`, `recycle`,
  `shadow_copy`, `fake_perms`, `netatalk`, `read_only` (partly covered by the
  share's `read_only`), `full_audit`, `acl_xattr`, `streams_depot`. Without
  them, migrations from Samba lose whatever the existing `smb.conf` relied on
  (most commonly the recycle bin and quota display).

---

## P3 — Fitting real clients and operators

### Samba configuration compatibility (§12, Appendix C)

- **`smb.conf` INI parsing** (`[global]`/`[share]` sections, case-insensitive
  parameter names, `#`/`;` comments, trailing-backslash continuation, quoted
  values) as an alternative to TOML. Without it, an existing Samba deployment
  has to be translated by hand before it can be tried, which is the single
  biggest barrier to adoption.
- **smb.conf parameter *semantics***: typed values (boolean `yes`/`no`/`1`/`0`,
  octal masks, lists, enumerations) and `%`-substitution variables (`%u`, `%g`,
  `%S`, `%m`, …) in path and command parameters. Without them, a syntactically
  accepted file behaves differently from the Samba it came from.
- **Registry-based configuration** (§12.3): `include = registry`, mixed mode and
  `registry shares = yes` under `HKLM\Software\Samba\smbconf`. Without it, a
  deployment whose shares are managed through the registry cannot be migrated.
- **The global parameters with behavioural meaning**: `security`,
  `passdb backend`, `workgroup`, `server string`, `netbios name`, `interfaces`,
  `bind interfaces only`, `log level` (0–10), `max log size`, `debug level`,
  `deadtime`, `socket options`, `max xmit`, `read raw`/`write raw`,
  `kernel oplocks`, `strict locking`, `max protocol`/`min protocol`,
  `encrypt passwords`, `username map`, `hosts allow`/`hosts deny`,
  `allow hosts`, `obey pam restrictions`, `idmap backend`/`idmap uid`/`idmap gid`,
  `local master`/`preferred master`/`os level`/`domain master`/`domain logons`,
  `load printers`/`printing`/`print command`, and the `* script` hooks. Without
  them, a translated configuration silently drops policy the operator believed
  was in force — which is why today's TOML parser rejects unknown keys instead of
  ignoring them.
- **The share parameters with behavioural meaning**: `read only` (`read_only`
  exists), `guest ok`/`public`/`guest only`/`guest account`, `valid users`/
  `invalid users`/`admin users`, `writeable`, `browseable`, `create mask`/
  `directory mask`, `veto files`/`hide files`, `case sensitive`,
  `strict locking`, `vfs objects`, `printable`, and `follow symlinks` (our
  symlink behaviour is fixed at Samba's `wide links` today). The user-list
  parameters are the visible face of per-share authorization in P0.
- **The remaining Appendix C parameters** that configure parts of the suite this
  server does not have (`winbind *`, `idmap *`, `announce as`/`announce version`,
  `browse list`, `lock directory`, `smb passwd file`,
  `logon drive`/`home`/`path`/`script`, printer scripts). They become relevant
  only if the corresponding subsystem is implemented.

### DCE/RPC over named pipes (§11.4, §19)

- **Named-pipe support over `IPC$`**: `SMB2_CREATE` of `\pipe\…`,
  read/write/transact on pipes, `FSCTL_PIPE_TRANSCEIVE`. Today `IPC$` is a stub
  that only answers IOCTL. Everything below depends on this, and without it some
  clients stall during connect rather than failing cleanly.
- **SRVSVC (`\srvsvc`)**: share enumeration. This is what `smbclient -L` and
  Explorer's "Network" view need. Without it, browsing shows nothing even though
  connecting by name works — the most visible "is this Samba?" test there is.
- **SAMR and LSARPC (`\samr`, `\lsarpc`)**: account and LSA lookups. Without
  them, Windows clients log "the trust relationship…" style warnings and
  user/group name resolution fails during negotiation.
- **WINREG (`\winreg`)**, **WKSSVC (`\wkssvc`)**, **SPOOLSS (`\spoolss`)**,
  **EVENTLOG (`\eventlog`)**. Without them, registry-based tooling, workstation
  enumeration, printer discovery and event log access are unavailable; each is a
  client feature that quietly does not work.
- **NETLOGON (`\netlogon`)**, needed for domain logons. Only relevant if a
  domain role is ever added, which *Settled* above says it will not be — listed
  for completeness of the spec surface, not as a plan.

### Identity, SIDs and authorization (§14)

- **SID↔uid/gid mapping** (`idmap`), the mechanism that lets on-disk permissions
  distinguish clients (also the foundation of per-share authorization in P0).
  Without it, a synthesized permissive security descriptor is all a client sees,
  so ACLs are meaningless and every client looks like the server's own user.
- **idmap backends**: `tdb`, `ldap`, `rid`, `autorid`, `ad`, `hash`, `rfc2307`,
  `script`. Without them, there is no way to make SIDs and Unix identities agree
  consistently across more than one host.
- **Group mapping** (`group_mapping.tdb` and `net groupmap`), plus the default
  mappings for built-in groups. Without it, Windows group membership cannot be
  expressed as a Unix group, so group-based access control is impossible.
- **Use the well-known SIDs/RIDs of Appendix E** (S-1-5-18/19/20,
  BUILTIN\Administrators/Users/Guests/…, RID 500/501/512–520) in a real security
  descriptor, an owner/group mapping and any SID-based ACL check. Today only
  `S-1-5-32-544` and `S-1-1-0` appear, in the synthesized permissive descriptor,
  so anything that inspects the descriptor sees a server with no notion of
  identity.

### Operational (§18)

- **Auditing hooks** equivalent to `extd_audit`/`full_audit` (per-operation
  audit records to a file or syslog). Without them, there is no record of who
  read or wrote what, which is usually a compliance blocker before it is a
  debugging one.
- **A `testparm`-equivalent validation mode.** `--check` validates and reports
  today, but the spec's tooling prints the resolved configuration *including
  defaults* for review. Without a diff-style report, an operator cannot see how
  a config differs from what they thought they wrote — `--dump-config` covers
  most of the need and is the reason this is low priority.
- **`socket options`** (e.g. `TCP_NODELAY`, `SO_SNDBUF`/`SO_RCVBUF`, keepalive),
  **`read raw`/`write raw`** and **`max xmit`** as configuration surfaces for the
  tuning this server currently applies with fixed constants. Without them, a
  deployment on a high-latency or high-bandwidth link cannot retune without a
  rebuild (see [docs/TUNING.md](docs/TUNING.md) for what is fixed today).
- **`kernel oplocks` and `strict locking` equivalents.** This server takes
  leases in its own table and uses OFD byte-range locks, but it has no
  kernel-oplock integration, so a local process and an SMB client can both think
  they own a file. Without it, mixing local and network access to the same share
  is unsafe — the reason the README tells you not to.

### Packaging and testing

- **A test/container image.** The host suites in `bench/` need root and
  cifs.ko; a container that runs a real client against the server would let the
  integration tests run in CI. Without it, the end-to-end behaviour that only a
  real client exercises is verified by hand before releases, not on every push.
- **Registered buffers / zero-copy for encrypted reads.** Encrypted payloads
  must be sealed, so they take the buffered path. Without it, a sealed read
  copies through userspace where an unsealed one is spliced — the throughput gap
  between `encrypt = true` and not is the price.
