# Roadmap

samba is at feature parity with the implementation it was ported from, at that
implementation's 1.4 level. This is what is deliberately *not* done yet, in
rough priority order. Everything here is a known limitation with a stated
reason, not an oversight — [SECURITY.md](SECURITY.md) and
[docs/PORTING.md](docs/PORTING.md) have the details.

## Specification conformance

[SPEC.md](SPEC.md) is a consolidated SAMBA specification covering the SMB2/SMB3
protocol *and* the wider Samba 3 suite (daemons, configuration, identity
mapping, VFS, administration, printing). Everything in it that this server does
not currently do is listed below as a TODO, grouped by the spec section it comes
from.

A note on scope, because it matters for reading this list: this project is an
**SMB 2.0.2–3.1.1 file server**, not a re-implementation of the Samba 3 suite.
Items that would turn it into something else (an SMB1/NBT stack, an NT4 domain
controller, a print server, a NetBIOS name daemon) are marked **[out of scope]**
with the reason. Everything unmarked is a genuine gap in *this* server's
SMB2/SMB3 feature set and is fair game to implement.

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

---

## TODO: SMB2/SMB3 protocol gaps (SPEC.md §5–9, §20, Appendix A/B)

### Transport (§5)

- [ ] **TODO**: NetBIOS over TCP transport on port 139 (RFC 1001/1002), which
  dialects 2.0.2–3.0.2 are specified to allow (§5.2). Today only direct TCP 445
  is served; an SMB1-only client gets the SMB2 wildcard and hangs.
- [ ] **TODO**: SMB2 RDMA transport ([MS-SMBD]) for dialects 3.0, 3.0.2 and
  3.1.1 (§5.3, §9.3). Needs RDMA hardware and a HCA path Go cannot reach without
  CGO — see [docs/SMBDIRECT.md](docs/SMBDIRECT.md).
- [ ] **TODO**: SMB over QUIC for 3.1.1 (§5.4, §9.4): UDP port 443 with the ALPN
  identifier `smb` (0x73 0x6D 0x62, §21.2).

### Negotiation contexts (§6.3)

- [ ] **TODO**: `COMPRESSION_CAPABILITIES` negotiate context (0x0003) and SMB3
  compression itself (algorithm negotiation, compressed data, `FSCTL` for
  compression) — not implemented at all today.
- [ ] **TODO**: `NETNAME_NEGOTIATE_CONTEXT` (0x0004), which carries the server's
  NetName for cluster/multichannel identification.
- [ ] **TODO**: `TRANSPORT_CAPABILITIES` (0x0005), which advertises the
  transports (including RDMA) a client may reconnect over.
- [ ] **TODO**: `SIGNING_CAPABILITIES` (0x0008): negotiate the SMB 3.1.1 signing
  algorithm (see AES-GMAC below) instead of always deriving AES-CMAC.
- [ ] **TODO**: `SMB2_IMPL_ID` context (0xF100), reporting the implementation
  name/version/GUID to clients.
- [ ] **TODO**: Honour the negotiate-context preference *ordering* the client
  sends (we currently take the first cipher we support, or the strongest when
  `prefer_aes256` is set).

### Message header and flags (§6.1, Appendix B)

- [ ] **TODO**: `SMB2_FLAGS_PRIORITY_MASK` (0x0070): accept and account for the
  priority field rather than ignoring it.
- [ ] **TODO**: `SMB2_FLAGS_DFS_OPERATIONS` (0x10000000): reject DFS operations
  explicitly with a clear status instead of treating them as ordinary requests.
- [ ] **TODO**: `SMB2_KEEPALIVE` (0x000D, Appendix A) — the spec's name for the
  opcode this server implements as ECHO. Same wire format and a successful empty
  reply, but confirm the keepalive semantics (and the "no response required"
  reading some clients take) and document the naming.

### Dialect-specific features (§9)

- [ ] **TODO**: Durable handles (SMB 2.0.2, §9.1): the `DHnQ`/`DH2Q`/`DHnC`
  create contexts, handle reconnection after a network outage, and
  `SMB2_TREE_CONNECT` on a reconnected handle.
- [ ] **TODO**: Resilient handles (SMB 2.1, §9.2) and persistent handles
  (SMB 3.0 / cluster, §9.3).
- [ ] **TODO**: Dynamic reauthentication (SMB 2.1, §9.2): a session-renewing
  `SESSION_SETUP` on an established session, including re-deriving keys.
- [ ] **TODO**: Scale-out / cluster features (SMB 3.0, §9.3): cluster reconnect
  contexts and the `CLUSTER_RECONNECT` handling.
- [ ] **TODO**: AES-GMAC signing for SMB 3.1.1 (§8.1, §9.4), negotiated through
  the `SIGNING_CAPABILITIES` context.
- [ ] **TODO**: 3.1.1 encryption-cipher negotiation beyond GCM/CCM as the spec
  allows (check AES-256 variants against the exact spec wording, and any future
  cipher ids).

### Security (§8, §20)

- [ ] **TODO**: Per-share encryption. The spec allows encryption to be enabled
  globally *or per share* (§8.2); today `encrypt` is server-wide only.
- [ ] **TODO**: Session key rotation / encryption key rotation on
  reauthentication (§20.2 requires "proper key derivation and rotation").
- [ ] **TODO**: Validate negotiate responses on the *client* side, if a client
  role is ever added (§20.3); the server side (`FSCTL_VALIDATE_NEGOTIATE_INFO`)
  is implemented.
- [ ] **TODO**: Downgrade protection ordering: prefer the highest dialect the
  client offers explicitly, and record why (we currently pick by our own
  preference order, which happens to put 3.1.1 first).

## TODO: Samba 3 suite gaps (SPEC.md §10–19, §21, Appendices C–E)

### Daemons and listeners (§10, §19)

- [ ] **[out of scope]**: `smbd` listening on **both** TCP 139 and TCP 445, with
  NetBIOS session service on 139 (§10.2). This server is direct-TCP only by
  design; port 139 needs an NBT stack (§5.2, §11.2).
- [ ] **[out of scope]**: `nmbd` (§10.3): NetBIOS name registration/resolution,
  WINS server, browse master election, datagram distribution on UDP 137/138.
  A name/browse daemon is a different service from an SMB file server.
- [ ] **[out of scope]**: `winbindd` (§10.4, §14): SID↔uid/gid mapping, NSS
  integration, and its caches. Identity mapping turns this into a domain member
  server.
- [ ] **[out of scope]**: a `passdb` abstraction layer with
  `auth`/`passdb`/`idmap` subsystems (§10.5). Follow-up work in scope for this
  server is per-share authorization (see the list above), not a passdb stack.

### SMB1/CIFS and legacy protocol (§11, Appendix D)

- [ ] **[out of scope]**: the SMB1 dialects LANMAN1, LANMAN2 and NT LM 0.12
  (§11.1, §19), including the whole SMB1 command set in Appendix D
  (NEGPROT, SESSION_SETUP_ANDX, TREE_CONNECT_ANDX, NT_CREATE_ANDX, TRANSACT2,
  FIND_FIRST2/NEXT2, FSCTL, EXTENDED_SECURITY, …). SMB1 has been removed from
  Windows clients and servers.
- [ ] **[out of scope]**: NetBIOS over TCP/IP (NetBT) name registration,
  resolution, session service on 139 and datagram service on UDP 138 (§11.2).

### CIFS extensions (§11.3)

- [ ] **TODO**: DFS referrals (`GET_DFS_REFERRAL`, the `SMB2_FLAGS_DFS_OPERATIONS`
  flag, and referral responses) so a namespace can be traversed. Today a DFS
  request is treated as an ordinary one.
- [ ] **TODO**: POSIX/UNIX extensions: symlink creation and reading, hard links,
  chmod/chown, and the UNIX information levels. (UTF-16LE on the wire and 64-bit
  offsets are already implemented.)
- [ ] **TODO**: Alternate data streams (§15.2 `streams_depot`): named streams on
  the wire (`file:stream` syntax) and `FileStreamInformation` for more than the
  default `::$DATA`.

### DCE/RPC and named pipes (§11.4, §19)

- [ ] **TODO**: Named-pipe support over IPC$ (`SMB2_CREATE` of `\pipe\…`,
  read/write/transact on pipes, `FSCTL_PIPE_TRANSCEIVE`), which today is a stub
  that only answers IOCTL.
- [ ] **TODO**: SRVSVC (`\srvsvc`): share enumeration — what `smbclient -L`
  and Explorer's share list need.
- [ ] **TODO**: SAMR and LSARPC (`\samr`, `\lsarpc`): account and LSA lookups.
- [ ] **TODO**: NETLOGON (`\netlogon`), needed for domain logons.
- [ ] **TODO**: WINREG (`\winreg`), SRVSVC, WKSSVC (`\wkssvc`), SPOOLSS
  (`\spoolss`), EVENTLOG (`\eventlog`).

### Configuration system (§12, Appendix C)

- [ ] **TODO**: `smb.conf` INI parsing (`[global]`/`[share]` sections,
  case-insensitive parameter names, `#`/`;` comments, trailing-backslash line
  continuation, quoted values) as an alternative to the TOML file, so existing
  Samba configuration can be reused.
- [ ] **TODO**: The smb.conf parameter *semantics*: typed values (boolean
  `yes`/`no`/`1`/`0`, octal masks, lists, enumerations), and `%`-substitution
  variables (`%u`, `%g`, `%S`, `%m`, …) in path and command parameters.
- [ ] **TODO**: Registry-based configuration (§12.3): `include = registry`,
  mixed mode, and `registry shares = yes` under
  `HKLM\Software\Samba\smbconf`.
- [ ] **TODO**: The global parameters with behavioural meaning: `security`,
  `passdb backend`, `workgroup`, `server string`, `netbios name`, `interfaces`,
  `bind interfaces only`, `log level` (0–10), `max log size`, `debug level`,
  `deadtime`, `socket options`, `max xmit`, `read raw`/`write raw`,
  `kernel oplocks`, `strict locking`, `max protocol`/`min protocol`,
  `encrypt passwords`, `username map`, `hosts allow`/`hosts deny`,
  `allow hosts`, `obey pam restrictions`, `idmap backend`/`idmap uid`/`idmap gid`,
  `local master`/`preferred master`/`os level`/`domain master`/`domain logons`,
  `load printers`/`printing`/`print command`, and the `* script`
  (`add user script`, `add share script`, …) hooks.
- [ ] **TODO**: The share parameters with behavioural meaning: `read only`
  (`read_only` exists), `guest ok`/`public`/`guest only`/`guest account`,
  `valid users`/`invalid users`/`admin users`, `writeable`, `browseable`,
  `create mask`/`directory mask`, `veto files`/`hide files`, `case sensitive`,
  `strict locking`, `vfs objects`, `printable`, and `follow symlinks` (our
  symlink behaviour is fixed at Samba's `wide links` semantics today).
- [ ] **TODO**: The remaining parameters in Appendix C that configure the parts
  of the suite this server does not have (`winbind *`, `idmap *`,
  `announce as`/`announce version`, `browse list`, `lock directory`,
  `smb passwd file`, `logon drive`/`home`/`path`/`script`, printer scripts) —
  they become relevant only if the corresponding subsystem is implemented.

### Authentication and security modes (§13)

- [ ] **TODO**: `security = share`: share-level credentials, independent of the
  session.
- [ ] **[out of scope]**: `security = server` (pass-through to another SMB
  server) — deprecated in the spec itself for man-in-the-middle exposure.
- [ ] **TODO**: `security = domain`: NT4 domain authentication via NETLOGON,
  including `net rpc join`.
- [ ] **TODO**: `security = ads`: AD member-server operation — Kerberos (✓
  implemented), LDAP directory lookups and DNS SRV service location are missing.
- [ ] **TODO**: `passdb backend` and its backends: `tdbsam`, `ldapsam`,
  `ldapsam_compat`, `mysql`, `xmlsam` and `guest`, with multiple backends chained
  in a list. Today users come from a static `[[user]]` list with NT hashes.
- [ ] **TODO**: `net ads join` / `net rpc join` and the join state a domain
  member needs.
- [ ] **[out of scope]**: NT4 Primary Domain Controller functionality — SAM
  database, NETLOGON service, LSARPC/SAMR, group mapping via `group_mapping.tdb`
  and `net groupmap` (§13.4).
- [ ] **TODO**: Clock-skew policy for Kerberos as a configurable value (the
  acceptor uses the library default today).

### Identity mapping (§14)

- [ ] **TODO**: SID↔uid/gid mapping (`idmap`), the mechanism that lets on-disk
  permissions distinguish clients (also tracked as per-share authorization
  above).
- [ ] **TODO**: idmap backends: `tdb`, `ldap`, `rid`, `autorid`, `ad`, `hash`,
  `rfc2307`, `script`.
- [ ] **TODO**: Group mapping (`group_mapping.tdb` and `net groupmap`), plus the
  default mappings for the built-in groups.
- [ ] **TODO**: Use the well-known SIDs/RIDs of Appendix E (S-1-5-18/19/20,
  BUILTIN\Administrators/Users/Guests/…, RID 500/501/512–520) in a real
  security descriptor, an owner/group mapping and any SID-based ACL check. Today
  only `S-1-5-32-544` and `S-1-1-0` appear, in the synthesized permissive
  descriptor.
- [ ] **[out of scope]**: NSS integration for `winbindd` (§14.1).

### VFS layer (§15)

- [ ] **TODO**: A stackable VFS layer with per-share module configuration
  (`vfs objects`), where each operation can be intercepted. The Go equivalent of
  a `.so` module is a compile-time plugin registration collected per share.
- [ ] **TODO**: The module interface (§15.3): an initialisation hook, an
  operations table and a deinitialisation hook, with a pass-through default
  module that modules override selectively.
- [ ] **TODO**: The named modules (§15.2): `default_quota`, `extd_audit`,
  `recycle`, `shadow_copy`, `fake_perms`, `netatalk`, `read_only` (partly covered
  by the share's `read_only`), `full_audit`, `acl_xattr`, `streams_depot`.

### Administrative interfaces (§16)

- [ ] **[out of scope]**: the `net` command and its `ads`/`rpc`/`rap` protocols
  (`net ads join`, `net rpc user/group/share`, `net groupmap`, `net sam`,
  `net registry`). An administration client is a separate program; if any of it
  is ever added, `net rpc share` and `net sam` need the DCE/RPC work above.
- [ ] **[out of scope]**: `pdbedit` and `smbpasswd` (§16.2, §16.3), which manage
  the passdb backends this server does not have.
- [ ] **[out of scope]**: SWAT (§16.4), the web administration interface on TCP
  901. This server deliberately has no HTTP listener.

### Print services (§17)

- [ ] **[out of scope]**: print shares and the `printable` share parameter,
  print spooling to a backend (CUPS, LPRng, BSD LPD, SysV, AIX, HPUX), the print
  command pipeline, print-job status, and driver management via `print$`
  (§17.1–17.3). This server serves files only; the spec's print surface needs the
  SPOOLSS RPC interface above.

### Operational (§18)

- [ ] **TODO**: Logging to a file as well as stderr, with `log file` (`%m`
  substitution), `max log size` and rotation, and the spec's 0–10 verbosity
  scale (this server has three levels: warn, info, debug).
- [ ] **TODO**: Auditing hooks equivalent to `extd_audit`/`full_audit`
  (per-operation audit records to a file or syslog).
- [ ] **TODO**: A `testparm`-equivalent configuration validation mode —
  `--check` validates today, but the spec's tooling prints the resolved
  configuration (including defaults) for review.
- [ ] **TODO**: `deadtime`: an idle-connection timeout in minutes (0 = never).
  This server deliberately never disconnects an idle connection; exposing the
  knob makes that policy explicit and tunable.
- [ ] **TODO**: `socket options` (e.g. `TCP_NODELAY`, `SO_SNDBUF`/`SO_RCVBUF`,
  keepalive), `read raw`/`write raw`, and `max xmit` as configuration surfaces
  for the tuning this server currently applies with fixed constants.
- [ ] **TODO**: `kernel oplocks` and `strict locking` equivalents: this server
  takes leases in its own table and uses OFD byte-range locks; the kernel-oplock
  integration Samba has (to avoid conflicts with local processes) is absent.

### Ports and identifiers (§21)

- [ ] **[out of scope]**: NetBIOS name service (UDP 137), NetBIOS datagram
  service (UDP 138) and the SWAT port (TCP 901) (§21.1).
- [ ] **TODO**: QUIC on UDP 443 with ALPN `smb` (§21.1, §21.2), tied to the QUIC
  transport item above.
