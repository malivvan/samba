# Consolidated SAMBA Protocol Specification (SMB2 + SMB3)

## Abstract

This document consolidates the SAMBA 2 protocol reference specification (covering SMB 2.0.2 through SMB 3.1.1) and the Samba 3 implementation specification (covering Samba versions 3.0 through 3.6). The SAMBA 2 protocol, commercially known as SMB2 and SMB3, provides file and print sharing services between networked machines. The Samba 3 suite is the primary open-source implementation of the SMB/CIFS protocol for UNIX-like operating systems. This consolidated specification defines the packet formats, protocol operations, security mechanisms, transport bindings, server architecture, configuration semantics, and administrative interfaces for both the protocol and its reference implementation.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Normative References](#2-normative-references)
3. [Terminology](#3-terminology)
4. [Protocol Overview](#4-protocol-overview)
5. [Transport Layer](#5-transport-layer)
6. [Message Format](#6-message-format)
7. [Protocol Operations](#7-protocol-operations)
8. [Security](#8-security)
9. [Dialect-Specific Features](#9-dialect-specific-features)
10. [Samba 3 Architecture](#10-samba-3-architecture)
11. [Samba 3 Protocol Implementation](#11-samba-3-protocol-implementation)
12. [Configuration System](#12-configuration-system)
13. [Authentication and Security (Samba 3)](#13-authentication-and-security-samba-3)
14. [Identity Mapping and Winbind](#14-identity-mapping-and-winbind)
15. [Virtual File System (VFS) Layer](#15-virtual-file-system-vfs-layer)
16. [Administrative Interfaces](#16-administrative-interfaces)
17. [Print Services](#17-print-services)
18. [Operational Considerations](#18-operational-considerations)
19. [Conformance Requirements](#19-conformance-requirements)
20. [Security Considerations](#20-security-considerations)
21. [IANA Considerations](#21-iana-considerations)
22. [References](#22-references)
23. [Appendix A: SMB2 Opcode Reference](#appendix-a-smb2-opcode-reference)
24. [Appendix B: SMB2 Flags](#appendix-b-smb2-flags)
25. [Appendix C: smb.conf Parameter Reference](#appendix-c-smbconf-parameter-reference)
26. [Appendix D: SMB Command Codes (SMB1/CIFS)](#appendix-d-smb-command-codes-smb1cifs)
27. [Appendix E: Well-Known SIDs and RIDs](#appendix-e-well-known-sids-and-rids)
28. [Appendix F: Change History](#appendix-f-change-history)

---

## 1. Introduction

### 1.1 Scope

This specification defines the wire protocol for the SAMBA 2 implementation of the Server Message Block protocol versions 2 and 3, as well as the architecture and operational characteristics of the Samba 3 implementation suite. The protocol supports:

- Sharing of file and print resources between machines
- Authenticated access to remote file systems
- Named pipe interprocess communication
- Multiple transport bindings including TCP, RDMA, and QUIC

The SAMBA 2 protocol is a cleanly re-designed variant of the original SMB protocol, with a significantly reduced command set and modernized packet formats. The Samba 3 suite provides the primary open-source implementation of the SMB/CIFS protocol for UNIX-like operating systems, covering versions 3.0 through 3.6.

### 1.2 Conformance Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119.

---

## 2. Normative References

The following documents are indispensable for the application of this specification:

- **[MS-SMB2]** — Server Message Block (SMB) Protocol Versions 2 and 3. Microsoft Open Specifications.
- **[MS-SMBD]** — SMB2 Remote Direct Memory Access (RDMA) Transport Protocol. Microsoft Open Specifications.
- **[MS-CIFS]** — Common Internet File System (CIFS) Protocol. Microsoft Open Specifications, 2024.
- **[MS-SMB]** — Server Message Block (SMB) Version 1.0 Protocol. Microsoft Open Specifications, 2024.
- **[MS-FSA]** — File System Algorithms. Microsoft Open Specifications.
- **[MS-RRP]** — Windows Remote Registry Protocol. Microsoft Open Specifications.
- **[MS-LSAD]** — Local Security Authority (Domain Policy) Remote Protocol. Microsoft Open Specifications.
- **[MS-SAMR]** — Security Account Manager (SAM) Remote Protocol. Microsoft Open Specifications.
- **[MS-NRPC]** — Netlogon Remote Protocol. Microsoft Open Specifications.
- **[MS-SRVS]** — Server Service Remote Protocol. Microsoft Open Specifications.
- **[MS-WKST]** — Workstation Service Remote Protocol. Microsoft Open Specifications.
- **[MS-RPRN]** — Print System Remote Protocol. Microsoft Open Specifications.
- **[MS-EVEN]** — EventLog Remoting Protocol. Microsoft Open Specifications.
- **[RFC 1001]** — Protocol Standard for a NetBIOS Service on a TCP/UDP Transport: Concepts and Methods.
- **[RFC 1002]** — Protocol Standard for a NetBIOS Service on a TCP/UDP Transport: Detailed Specifications.
- **[RFC 2119]** — Key words for use in RFCs to Indicate Requirement Levels.
- **[RFC 2307]** — An Approach for Using LDAP as a Network Information Service.
- **[RFC 5040]** — A Remote Direct Memory Access Protocol Specification.
- **[RFC 5041]** — Direct Data Placement over Reliable Transports.
- **[RFC 9000]** — QUIC: A UDP-Based Multiplexed and Secure Transport.
- **[X/Open CAE]** — Protocols for X/Open PC Interworking: SMB, Version 2. X/Open Company, Ltd., 1992.

---

## 3. Terminology

| Term | Definition |
|------|------------|
| **Client** | The machine initiating SMB2 requests |
| **Server** | The machine responding to SMB2 requests |
| **Dialect** | A specific version of the SMB2 protocol family |
| **Negotiate Context** | A TLV-encoded extension mechanism for protocol negotiation |
| **Durable Handle** | A file handle that survives short network outages |
| **Lease** | A caching mechanism allowing clients to cache file data |
| **Multi-Credit** | A mechanism allowing larger data transfers per request |
| **SMB** | Server Message Block — the file sharing protocol originally developed by IBM/Microsoft |
| **CIFS** | Common Internet File System — Microsoft's extension of SMB, documented in IETF drafts |
| **NetBIOS** | Network Basic Input/Output System — naming and session layer used by legacy SMB |
| **Passdb** | Password database — the storage abstraction for user credentials |
| **idmap** | Identity mapping — the subsystem for translating Windows SIDs to UNIX UIDs/GIDs |
| **VFS** | Virtual File System — a stackable module layer between Samba and the underlying filesystem |
| **TDB** | Trivial Database — a simple key-value store used by Samba for persistent state |
| **SID** | Security Identifier — Windows security principal identifier |
| **RID** | Relative Identifier — the variable portion of a SID |
| **PDC** | Primary Domain Controller |
| **BDC** | Backup Domain Controller |

---

## 4. Protocol Overview

### 4.1 Design Principles

The SAMBA 2 protocol was designed with the following objectives:

1. **Simplification:** Reduce the number of protocol operations from approximately 100 in SMB1 to 19 in SMB2.
2. **Handle-based Operations:** All file operations are handle-based, with 16-byte file identifiers used throughout.
3. **Asynchronous Support:** Native support for asynchronous request/response patterns.
4. **Modern Security:** Mandatory signing with AES-based algorithms, optional encryption.
5. **Scalability:** Support for large MTU, multi-channel, and RDMA transports.

### 4.2 Protocol Versions

The SAMBA 2 protocol encompasses multiple dialects:

| Dialect | Version Code | Introduction | Key Features |
|---------|-------------|--------------|--------------|
| SMB 2.0.2 | 0x0202 | Windows Vista / Server 2008 | Base protocol, durable handles |
| SMB 2.1 | 0x0210 | Windows 7 / Server 2008 R2 | Leases, multi-credit, resilient handles |
| SMB 3.0 | 0x0300 | Windows 8 / Server 2012 | Encryption, secure negotiation, multi-channel |
| SMB 3.0.2 | 0x0302 | Windows 8.1 / Server 2012 R2 | RDMA transport improvements |
| SMB 3.1.1 | 0x0311 | Windows 10 / Server 2016 | Pre-authentication integrity, AES-128-GCM |

---

## 5. Transport Layer

### 5.1 Direct TCP Transport

The Direct TCP transport is supported by all SAMBA 2 dialects. The transport packet header has the following structure:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Zero  |        StreamProtocolLength          | SMB2Message   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| Zero | 1 byte | MUST be set to 0x00 |
| StreamProtocolLength | 3 bytes | Length of SMB2Message in network byte order, excluding the 4-byte header |
| SMB2Message | variable | The SMB2 packet body |

### 5.2 NetBIOS over TCP Transport

SMB2 dialects 2.0.2, 2.1, 3.0, and 3.0.2 allow operation over NetBIOS over TCP as specified in RFC 1001 and RFC 1002.

### 5.3 RDMA Transport

SMB2 dialects 3.0, 3.0.2, and 3.1.1 support the SMB2 RDMA Transport as specified in [MS-SMBD]. This transport allows SMB2 packets to be delivered over RDMA-capable transports such as iWARP or InfiniBand.

### 5.4 QUIC Transport

SMB2 dialect 3.1.1 supports operation over QUIC transport as specified in RFC 9000. When negotiated, the protocol operates over UDP port 443 with the ALPN identification sequence 0x73 0x6D 0x62 ("smb").

---

## 6. Message Format

### 6.1 SMB2 Packet Header

Every SMB2 message begins with a 64-byte header. The header has two forms depending on whether the `SMB2_FLAGS_ASYNC_COMMAND` bit is set.

#### 6.1.1 Synchronous Header

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   ProtocolId (4 bytes)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  StructureSize |   CreditCharge  |         Status/Channel      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Command                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           CreditReq                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Flags                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         NextCommand                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         MessageId (8 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Reserved / AsyncId (8 bytes)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         TreeId (4 bytes)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       SessionId (8 bytes)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Signature (16 bytes)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| ProtocolId | 0 | 4 | MUST be 0xFE 'S' 'M' 'B' (0xFE534D42) |
| StructureSize | 4 | 2 | MUST be 64 |
| CreditCharge | 6 | 2 | Credits charged for this request |
| Status/Channel | 8 | 4 | NTSTATUS code (response) or Channel (request) |
| Command | 12 | 2 | SMB2 command code |
| CreditRequest | 14 | 2 | Credits requested |
| Flags | 16 | 4 | SMB2 flags |
| NextCommand | 20 | 4 | Offset to next command in compound request |
| MessageId | 24 | 8 | Message identifier |
| Reserved | 32 | 4 | Reserved (sync) or AsyncId (async) |
| TreeId | 36 | 4 | Tree identifier |
| SessionId | 40 | 8 | Session identifier |
| Signature | 48 | 16 | Message signature |

#### 6.1.2 Asynchronous Header

When the `SMB2_FLAGS_ASYNC_COMMAND` flag is set, the `Reserved` field is replaced by:

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| AsyncId | 32 | 8 | Asynchronous operation identifier |

### 6.2 Command Codes

The SAMBA 2 protocol defines the following command codes:

| Command | Value | Description |
|---------|-------|-------------|
| SMB2_NEGOTIATE | 0x0000 | Protocol negotiation |
| SMB2_SESSION_SETUP | 0x0001 | Authentication and session establishment |
| SMB2_LOGOFF | 0x0002 | Session termination |
| SMB2_TREE_CONNECT | 0x0003 | Share connection |
| SMB2_TREE_DISCONNECT | 0x0004 | Share disconnection |
| SMB2_CREATE | 0x0005 | File/directory creation or opening |
| SMB2_CLOSE | 0x0006 | File handle closure |
| SMB2_FLUSH | 0x0007 | Buffer flush |
| SMB2_READ | 0x0008 | Data read |
| SMB2_WRITE | 0x0009 | Data write |
| SMB2_LOCK | 0x000A | Byte-range locking |
| SMB2_IOCTL | 0x000B | Device control |
| SMB2_CANCEL | 0x000C | Request cancellation |
| SMB2_KEEPALIVE | 0x000D | Connection keepalive |
| SMB2_QUERY_DIRECTORY | 0x000E | Directory enumeration |
| SMB2_CHANGE_NOTIFY | 0x000F | Change notification |
| SMB2_QUERY_INFO | 0x0010 | Information retrieval |
| SMB2_SET_INFO | 0x0011 | Information setting |
| SMB2_OPLOCK_BREAK | 0x0012 | Opportunistic lock break |

### 6.3 Negotiate Contexts

The SMB2 NEGOTIATE_CONTEXT structure is used to encode additional properties during protocol negotiation. Each context follows a TLV (Type-Length-Value) format:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        ContextType            |         DataLength            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Reserved                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Data (variable)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| ContextType | 2 bytes | Type identifier for the context |
| DataLength | 2 bytes | Length of the Data field |
| Reserved | 4 bytes | Reserved, MUST be zero |
| Data | variable | Context-specific data |

The following context types are defined:

| Context Type | Value | Description |
|--------------|-------|-------------|
| PREAUTH_INTEGRITY_CAPABILITIES | 0x0001 | Pre-authentication integrity |
| ENCRYPTION_CAPABILITIES | 0x0002 | Encryption algorithm negotiation |
| COMPRESSION_CAPABILITIES | 0x0003 | Compression algorithm negotiation |
| NETNAME_NEGOTIATE_CONTEXT | 0x0004 | NetName negotiation |
| TRANSPORT_CAPABILITIES | 0x0005 | Transport capabilities |
| SIGNING_CAPABILITIES | 0x0008 | Signing algorithm negotiation |
| SMB2_IMPL_ID | 0xF100 | Implementation identification |

---

## 7. Protocol Operations

### 7.1 Negotiation

The negotiation phase allows the client and server to determine which dialect of the SAMBA 2 protocol to use. The client sends an SMB2 NEGOTIATE Request containing a list of supported dialects. The server responds with the selected dialect.

#### 7.1.1 SMB 2.0.2 Negotiation

When the server detects the dialect string "SMB 2.002" in the client's dialect list, it MUST respond with an SMB2 NEGOTIATE Response with specific values:

- `DialectRevision` MUST be set to 0x0202
- `SecurityMode` MUST have the `SMB2_NEGOTIATE_SIGNING_ENABLED` bit set
- `MaxTransactSize` is set to the maximum buffer size for QUERY_INFO, QUERY_DIRECTORY, SET_INFO, and CHANGE_NOTIFY operations

#### 7.1.2 SMB 3.1.1 Negotiation

For the SMB 3.1.1 dialect (version code 0x0311), the client MUST set the dialect value in the Dialects array to 0x0311. This dialect introduces:

- Pre-authentication integrity verification
- Negotiable encryption with AES-128-GCM cipher
- Enhanced signing algorithms including AES-CMAC and AES-GMAC

### 7.2 Session Setup

The SMB2_SESSION_SETUP command establishes an authenticated context on the connection. The session key returned by the authentication mechanism is used to generate keys for signing, encryption, and decryption.

### 7.3 Tree Connect

The SMB2_TREE_CONNECT command connects the session to a specific share on the server. A TreeId is assigned to identify the connection.

### 7.4 File Operations

All file operations use a 16-byte file identifier (PersistentFileId + VolatileFileId) obtained from the SMB2_CREATE operation. The following operations are supported:

- **CREATE:** Opens or creates a file/directory
- **READ:** Reads data from an open file handle
- **WRITE:** Writes data to an open file handle
- **CLOSE:** Closes a file handle
- **FLUSH:** Flushes buffered data
- **QUERY_INFO:** Retrieves file metadata
- **SET_INFO:** Modifies file metadata

---

## 8. Security

### 8.1 Signing

All SAMBA 2 dialects support message signing to ensure integrity and authenticity. The signing algorithm varies by dialect:

| Dialect | Signing Algorithm |
|---------|------------------|
| SMB 2.0.2 | HMAC-SHA256 |
| SMB 2.1 | HMAC-SHA256 |
| SMB 3.0 | AES-CMAC |
| SMB 3.0.2 | AES-CMAC |
| SMB 3.1.1 | AES-CMAC, AES-GMAC |

Signing cannot be disabled by design for the SMB2 protocol. The signature field in the SMB2 header is 16 bytes and is computed over the entire SMB2 message with the signature field zeroed.

### 8.2 Encryption

SMB 3.x dialects optionally support encryption. The encryption algorithm is negotiated during the negotiate phase using the ENCRYPTION_CAPABILITIES context. Supported algorithms include:

- AES-128-CCM
- AES-128-GCM

Encryption can be enabled globally or per-share. When enabled, all SMB2 messages are encrypted using the session key derived during authentication.

### 8.3 Pre-Authentication Integrity

The SMB 3.1.1 dialect introduces pre-authentication integrity using the PREAUTH_INTEGRITY_CAPABILITIES negotiate context. This mechanism protects the negotiation exchange from tampering by including a hash of the negotiate request and response.

---

## 9. Dialect-Specific Features

### 9.1 SMB 2.0.2

- Base protocol implementation
- Durable file handles for short network outages
- Handle-based file operations

### 9.2 SMB 2.1

- **Leases:** Improved caching mechanism
- **Multi-Credit:** Large MTU support for reduced round trips
- **Resilient File Handles:** Enhanced durability guarantees
- **Dynamic Reauthentication:** Proactive session renewal

### 9.3 SMB 3.0

- **Encryption:** SMB-level encryption support
- **Secure Negotiation:** Protection against downgrade attacks
- **Multi-Channel:** Multiple network connections per session
- **SMB Direct:** RDMA transport support
- **Cluster Features:** Scale-out file server support

### 9.4 SMB 3.1.1

- **Pre-Authentication Integrity:** Enhanced negotiation security
- **AES-128-GCM:** Modern encryption cipher support
- **QUIC Transport:** SMB over QUIC on UDP port 443
- **Enhanced Signing:** AES-GMAC signing algorithm

---

## 10. Samba 3 Architecture

### 10.1 Process Model

Samba 3 operates as a set of cooperating daemons and utility programs. The core daemons are **smbd**, **nmbd**, and **winbindd**. Each daemon is responsible for a distinct aspect of the SMB/CIFS service.

```
┌─────────────────────────────────────────────────────────────┐
│                   Samba 3 Suite                             │
│  ┌─────────┐  ┌─────────┐  ┌───────────┐                   │
│  │  smbd   │  │  nmbd   │  │ winbindd  │                   │
│  │ (SMB/CIFS│  │(NetBIOS │  │ (ID map)  │                   │
│  │  Server) │  │  Name)  │  │           │                   │
│  └────┬────┘  └────┬────┘  └─────┬─────┘                   │
│       │            │              │                         │
│  ┌────▼────────────▼──────────────▼─────┐                   │
│  │         passdb / idmap / VFS          │                   │
│  │         Module Subsystems             │                   │
│  └───────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

### 10.2 smbd — SMB/CIFS Server Daemon

The **smbd** daemon is responsible for:

- Providing file and print services to SMB/CIFS clients.
- Handling SMB protocol negotiation, session setup, and tree connect operations.
- Enforcing share-level and user-level security policies.
- Managing file locking, oplocks, and change notification.
- Executing VFS module stacks for each share.
- Serving DCE/RPC endpoints over named pipes.

The daemon **MUST** listen on TCP ports 139 (NetBIOS Session Service) and 445 (SMB over TCP). It **MAY** also listen on UDP port 137/138 for legacy NetBIOS datagram services.

### 10.3 nmbd — NetBIOS Name Service Daemon

The **nmbd** daemon implements:

- NetBIOS name registration and resolution.
- WINS (Windows Internet Name Service) server functionality.
- Network browsing and domain master browser election.
- NetBIOS datagram distribution for legacy clients.

nmbd **MUST** listen on UDP ports 137 (Name Service) and 138 (Datagram Service).

### 10.4 winbindd — Identity Mapping Daemon

The **winbindd** daemon provides:

- Mapping of Windows SIDs to UNIX UIDs and GIDs.
- Integration with the Name Service Switch (NSS) subsystem.
- Caching of identity mappings in TDB files.
- Support for multiple idmap backends (tdb, ldap, rid, autorid, ad, hash, rfc2307).

winbindd operates independently of smbd and nmbd and **MAY** be disabled in environments where only local authentication is used.

### 10.5 Internal Architecture

Samba 3 employs a modular internal architecture. The SMB protocol handling layer sits above a **passdb** abstraction layer, which provides user and group credential storage. Above the passdb layer, the **auth** subsystem performs authentication and authorisation decisions. The VFS layer intercepts all filesystem operations, enabling stackable modules for features such as auditing, recycle bin, and shadow copy.

---

## 11. Samba 3 Protocol Implementation

### 11.1 SMB Protocol Dialects

Samba 3 supports the following SMB dialects:

| Dialect | Description | Availability |
|---------|-------------|-------------|
| **LANMAN1** | First modern SMB dialect with long filename support | All Samba 3 versions |
| **LANMAN2** | Extensions to LANMAN1 | All Samba 3 versions |
| **NT LM 0.12** | Windows NT LAN Manager dialect; also known as CIFS | All Samba 3 versions |
| **SMB 2.0** | Re-implementation of the SMB protocol; reduced command set | Samba 3.6+ (excluding durable file handles) |
| **SMB 2.1** | Minor enhancements to SMB 2.0 | Samba 3.6+ (partial) |

By default, Samba 3 negotiates the highest mutually supported dialect. The `max protocol` and `min protocol` parameters **MAY** be used to constrain negotiation.

### 11.2 NetBIOS over TCP/IP

Samba 3 implements NetBIOS over TCP/IP (NetBT) as specified in RFC 1001 and RFC 1002. The implementation provides:

- **Name Registration** — Registration of NetBIOS names for the Samba server and its workgroup/domain.
- **Name Resolution** — Resolution of NetBIOS names via broadcast or WINS.
- **Session Service** — Establishment of NetBIOS sessions on TCP port 139.
- **Datagram Service** — Distribution of NetBIOS datagrams on UDP port 138.

For environments where NetBIOS is not required, Samba **MAY** be configured to operate in "port 445 only" mode by disabling NetBIOS entirely.

### 11.3 CIFS Extensions

Samba 3 implements the CIFS extensions documented in [MS-CIFS] and [MS-SMB]. Key extensions include:

- **Extended Security** — NTLMv2 and Kerberos authentication via SPNEGO.
- **DFS (Distributed File System)** — Referral support for namespace traversal.
- **UNICODE** — Native UTF-16LE encoding on the wire, required for newer NT/2KX protocols.
- **Large File Support** — 64-bit file offsets.
- **POSIX Extensions** — UNIX-specific extensions for permissions, symlinks, and hard links.

### 11.4 DCE/RPC and Named Pipes

Samba 3 provides DCE/RPC services over SMB named pipes. The following interfaces are implemented:

| Interface | Named Pipe | Specification |
|-----------|-----------|---------------|
| **SAMR** | `\samr` | [MS-SAMR] |
| **LSARPC** | `\lsarpc` | [MS-LSAD] |
| **NETLOGON** | `\netlogon` | [MS-NRPC] |
| **WINREG** | `\winreg` | [MS-RRP] |
| **SRVSVC** | `\srvsvc` | [MS-SRVS] |
| **WKSSVC** | `\wkssvc` | [MS-WKST] |
| **SPOOLSS** | `\spoolss` | [MS-RPRN] |
| **EVENTLOG** | `\eventlog` | [MS-EVEN] (limited) |

---

## 12. Configuration System

### 12.1 smb.conf File Format

The primary configuration file is `smb.conf`, typically located at `/etc/samba/smb.conf`. The file **MUST** use an INI-style syntax with the following structure:

```ini
[global]
    parameter = value
    ...

[share_name]
    parameter = value
    ...
```

- Section names enclosed in square brackets define configuration contexts.
- `[global]` applies to the server as a whole.
- Other sections define individual shares.
- Parameter names are case-insensitive.
- Comments begin with `#` or `;`.
- Line continuation is indicated by a trailing backslash (`\`).
- Values containing spaces **SHOULD** be enclosed in double quotes.

### 12.2 Parameter Types and Semantics

Parameters in `smb.conf` are typed. The following value types are defined:

| Type | Description | Example |
|------|-------------|---------|
| **Boolean** | `yes`/`no`, `true`/`false`, `1`/`0` | `browseable = yes` |
| **Integer** | Signed or unsigned integer | `max log size = 5000` |
| **String** | Arbitrary text | `server string = Samba Server` |
| **Path** | Filesystem path | `path = /srv/samba/data` |
| **List** | Comma- or space-separated values | `valid users = alice, bob` |
| **Enumeration** | Predefined set of values | `security = user` |
| **Command** | Shell command with substitution variables | `add user script = /usr/sbin/useradd %u` |

Substitution variables (e.g., `%u` for username, `%g` for group, `%S` for share name) **MAY** be used in command and path parameters.

### 12.3 Registry-Based Configuration

Starting with Samba 3.2.0, configuration **MAY** be stored in the internal registry database under the key `HKLM\Software\Samba\smbconf`. Registry-based configuration can be activated in three modes:

1. **Registry-only** — `include = registry` in `[global]`.
2. **Mixed** — `include = registry` with fallback to file-based parameters.
3. **Registry shares** — `registry shares = yes` enables shares defined in the registry.

### 12.4 Key Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `security` | Enum | `user` | Security mode: `user`, `share`, `server`, `domain`, `ads` |
| `passdb backend` | List | `smbpasswd` | Password storage backend(s) |
| `workgroup` | String | `WORKGROUP` | NetBIOS workgroup/domain name |
| `server string` | String | `Samba` | Descriptive server string |
| `netbios name` | String | Hostname | NetBIOS name of the server |
| `interfaces` | List | All | Network interfaces to listen on |
| `bind interfaces only` | Boolean | `no` | Restrict listening to specified interfaces |
| `log level` | Integer | `0` | Debug verbosity level (0–10) |
| `max log size` | Integer | `5000` | Maximum log file size in KB |
| `load printers` | Boolean | `yes` | Enable printer sharing |
| `printing` | Enum | `cups` | Printing backend |
| `idmap backend` | String | `tdb` | Identity mapping backend |
| `vfs objects` | List | (none) | VFS modules to load for a share |

---

## 13. Authentication and Security (Samba 3)

### 13.1 Security Modes

Samba 3 supports five security modes, specified by the `security` parameter:

#### 13.1.1 `security = share`

Share-level security. The client authenticates to each share independently. This mode is deprecated and **SHOULD NOT** be used in new deployments.

#### 13.1.2 `security = user` (Default)

User-level security. The client **MUST** authenticate with a valid username and password before accessing any share. The server maps the authenticated user to a UNIX account for file access.

#### 13.1.3 `security = server`

Server-level security. Samba passes authentication requests to another SMB server (typically a Windows NT PDC). If the remote authentication fails, Samba **MAY** fall back to `security = user`. This mode is deprecated and **SHOULD NOT** be used due to man-in-the-middle vulnerability concerns.

#### 13.1.4 `security = domain`

Domain-level security. Samba validates credentials against a Windows NT4 domain controller using the NETLOGON protocol. The server **MUST** have been joined to the domain using the `net rpc join` command. Encrypted passwords **MUST** be enabled.

#### 13.1.5 `security = ads`

Active Directory security. Samba operates as a member server in an Active Directory domain, using Kerberos for authentication and LDAP for directory lookups. The server **MUST** have been joined to the AD domain using `net ads join`.

### 13.2 Password Storage Backends

The `passdb backend` parameter specifies one or more password storage mechanisms. The following backends are defined:

| Backend | Storage | Status |
|---------|---------|--------|
| **smbpasswd** | Flat file (`smbpasswd`) | Obsoleted; default for backward compatibility |
| **tdbsam** | TDB binary file (`passdb.tdb`) | Actively maintained |
| **ldapsam** | LDAP directory | Actively maintained |
| **ldapsam_compat** | LDAP with legacy schema | Compatibility mode |
| **mysql** | MySQL database | Third-party |
| **xmlsam** | XML file | Third-party |
| **guest** | Guest-only | Fallback for unknown users |

Multiple backends **MAY** be specified in a comma-separated list (e.g., `passdb backend = tdbsam, guest`). The `guest` backend **SHOULD** be included to handle unknown users gracefully.

### 13.3 Kerberos and Active Directory Integration

When operating in `security = ads` mode, Samba 3 uses:

- **Kerberos 5** — For user authentication against the AD domain.
- **LDAP** — For retrieval of user and group information from Active Directory.
- **DNS** — For service location (SRV records).

The `krb5.conf` file **MUST** be correctly configured, and the system clock **MUST** be synchronised with the domain controller (Kerberos requires time skew of less than 5 minutes).

### 13.4 Windows NT4 Domain Control

Samba 3 can function as a Windows NT4-style Primary Domain Controller (PDC). Required capabilities include:

- **SAM Database** — Storage of user and machine accounts in passdb.
- **NETLOGON Service** — Authentication of domain logons.
- **LSARPC** — Local Security Authority remote procedure calls.
- **SAMR** — Security Account Manager remote procedure calls.
- **Group Mapping** — Mapping of Windows groups to UNIX groups via `group_mapping.tdb`.

To join a Windows NT4 domain, the `net rpc join` command **MUST** be used with credentials of a domain administrator.

---

## 14. Identity Mapping and Winbind

### 14.1 ID Mapping Architecture

The idmap subsystem translates between Windows Security Identifiers (SIDs) and UNIX user/group IDs. The mapping is bidirectional and persistent, stored in TDB files by default. The `winbindd` daemon manages the mapping process and caches results.

The mapping process operates as follows:

1. A Windows SID is received (e.g., from an SMB request).
2. winbindd checks the cache for an existing mapping.
3. If not found, winbindd queries the configured idmap backend.
4. The backend returns a UNIX UID/GID or allocates a new one.
5. The mapping is stored in the cache and returned.

### 14.2 idmap Backends

| Backend | Method | Use Case |
|---------|--------|----------|
| **tdb** | Local TDB file | Default; single-server deployments |
| **ldap** | LDAP directory | Shared mappings across multiple servers |
| **rid** | Algorithmic (RID + base) | Read-only; predictable IDs |
| **autorid** | Algorithmic with automatic range | Multi-domain environments |
| **ad** | LDAP (Active Directory) | AD-native mapping |
| **hash** | Hash-based | Deterministic mapping |
| **rfc2307** | LDAP (RFC 2307 attributes) | Existing LDAP identity infrastructure |
| **script** | External script | Custom mapping logic |

### 14.3 Group Mapping

Windows groups are mapped to UNIX groups via the `group_mapping.tdb` file. This mapping is essential for domain controller functionality and for access control based on Windows group membership. The `net groupmap` command **MUST** be used to create and manage group mappings.

Built-in groups (e.g., `BUILTIN\Administrators`, `BUILTIN\Users`) have default mappings that **MAY** be overridden by the administrator.

---

## 15. Virtual File System (VFS) Layer

### 15.1 VFS Architecture

Samba 3 introduces a **stackable VFS** layer. Every filesystem operation performed by smbd passes through the VFS stack before reaching the underlying POSIX filesystem. VFS modules **MAY** intercept, modify, or augment operations.

VFS modules are loaded on a per-share basis via the `vfs objects` parameter. Modules are stacked in the order specified:

```ini
[share]
    vfs objects = audit recycle shadow_copy
```

### 15.2 Included VFS Modules

| Module | Purpose |
|--------|---------|
| **default_quota** | Enables Windows Explorer quota display |
| **extd_audit** | Extended auditing to log files and syslog |
| **recycle** | Recycle bin functionality for deleted files |
| **shadow_copy** | MS Shadow Copy Services–like functionality |
| **fake_perms** | Read-only profile support |
| **netatalk** | AppleTalk metadata support |
| **read_only** | Enforce read-only access |
| **full_audit** | Comprehensive operation auditing |
| **acl_xattr** | Extended ACL storage in extended attributes |
| **streams_depot** | Alternate data stream support |

### 15.3 VFS Module Interface

A VFS module is a shared library (`.so` file) that implements the Samba VFS interface. The interface consists of:

- **Initialisation function** — Called during module load to register implemented operations.
- **Operations table** — A structure containing function pointers for supported VFS operations.
- **Deinitialisation function** — Called during module unload.

The default module (`vfs_default.c`) provides pass-through implementations for all operations, allowing modules to selectively override specific functions.

---

## 16. Administrative Interfaces

### 16.1 net Command

The `net` command is the primary remote and local administration tool for Samba 3. It **MUST** support the following protocols:

- **ADS** — Active Directory operations.
- **RAP** — Remote Administration Protocol (legacy Windows 9x/NT3).
- **RPC** — Remote Procedure Call (NT4 and Windows 2000+).

Key subcommands include:

| Subcommand | Description |
|-----------|-------------|
| `net ads join` | Join an Active Directory domain |
| `net rpc join` | Join an NT4 domain |
| `net rpc user` | Manage user accounts |
| `net rpc group` | Manage group accounts |
| `net rpc share` | Manage shares |
| `net groupmap` | Manage group mappings |
| `net sam` | SAM database operations |
| `net registry` | Registry operations |

### 16.2 pdbedit Command

The `pdbedit` utility manages the passdb backend. It **MUST** support:

- Creation and deletion of user accounts.
- Modification of account attributes (password, full name, home directory, etc.).
- Listing and querying of account information.
- Migration between passdb backends.

### 16.3 smbpasswd Command

The `smbpasswd` utility manages the legacy `smbpasswd` flat-file backend. It is retained for backward compatibility but **SHOULD** be replaced by `pdbedit` in new deployments.

### 16.4 SWAT Web Interface

The Samba Web Administration Tool (SWAT) provides a browser-based interface for configuration management. SWAT **MUST** run on TCP port 901 and **SHOULD** be restricted to trusted networks. SWAT requires the `swat` binary and the `inetd`/`xinetd` super-server.

---

## 17. Print Services

### 17.1 Print Server Architecture

Samba 3 supports multiple print server backends:

| Backend | Description |
|---------|-------------|
| **CUPS** | Common UNIX Printing System (recommended) |
| **LPRng** | LPR Next Generation |
| **BSD LPD** | Traditional BSD print spooler |
| **SysV** | System V print spooler |
| **AIX** | IBM AIX print spooler |
| **HPUX** | HP-UX print spooler |

The `printing` parameter selects the backend. The `print command` parameter **MUST** specify the command used to submit print jobs.

### 17.2 Print Spooling

When a print job arrives, Samba:

1. Writes the job data to a spool directory specified by the `path` parameter of the printer share.
2. Executes the configured print command to submit the job to the backend spooler.
3. Monitors the job status and reports it to the client via the SPOOLSS RPC interface.

### 17.3 Driver Management

Samba supports the upload and management of Windows printer drivers via the `print$` share. The `add printer command`, `delete printer command`, and related parameters enable automatic printer creation from Windows clients.

---

## 18. Operational Considerations

### 18.1 Diagnostic Procedures

The following diagnostic steps **SHOULD** be performed when troubleshooting Samba issues:

1. **Validate name resolution** — Ensure DNS and/or WINS is functioning correctly.
2. **Validate smb.conf** — Run `testparm` to check for syntax errors.
3. **Inspect log files** — Increase `log level` to 3 or higher for detailed debugging.
4. **Verify network connectivity** — Use `smbclient -L localhost` to test the local server.
5. **Check NetBIOS name registration** — Use `nmblookup` to verify name registration.
6. **Review firewall rules** — Ensure TCP 139/445 and UDP 137/138 are permitted.

### 18.2 Logging and Auditing

Samba 3 writes logs to files specified by the `log file` parameter (default: `/var/log/samba/log.%m`, where `%m` is the client machine name). The `log level` parameter controls verbosity, ranging from 0 (errors only) to 10 (maximum debug output).

The `extd_audit` and `full_audit` VFS modules provide operation-level auditing to log files or syslog.

### 18.3 Performance Tuning

Key performance parameters include:

| Parameter | Effect |
|-----------|--------|
| `socket options` | TCP socket tuning (e.g., `TCP_NODELAY`, `SO_SNDBUF`) |
| `read raw` / `write raw` | Enable raw SMB read/write for large transfers |
| `max xmit` | Maximum SMB packet size |
| `deadtime` | Idle connection timeout (minutes) |
| `oplocks` | Opportunistic locking for caching |
| `kernel oplocks` | Kernel-level oplock support |
| `strict locking` | Per-read/write locking (performance impact) |

---

## 19. Conformance Requirements

A conforming Samba 3 implementation **MUST**:

1. Implement the SMB dialects LANMAN1, LANMAN2, and NT LM 0.12.
2. Support the `user` and `share` security modes.
3. Provide the `smbd`, `nmbd`, and `winbindd` daemons.
4. Implement the `smb.conf` configuration file format.
5. Support the `tdbsam` password backend.
6. Implement the VFS module loading interface.
7. Provide the `net`, `pdbedit`, and `smbpasswd` administrative utilities.
8. Support CUPS and at least one traditional print spooler backend.
9. Implement the SAMR, LSARPC, and NETLOGON DCE/RPC interfaces for domain controller functionality.

A conforming implementation **SHOULD**:

1. Support the `domain` and `ads` security modes.
2. Implement the `ldapsam` password backend.
3. Support SMB 2.0 (Samba 3.6 and later).
4. Implement the `winbindd` idmap architecture with at least the `tdb` and `rid` backends.
5. Support registry-based configuration (Samba 3.2 and later).

---

## 20. Security Considerations

### 20.1 Signing Requirements

Implementers MUST ensure that message signing is properly implemented. The signature verification process requires:

1. Zeroing the 16-byte signature field in the SMB2 header
2. Computing the HMAC or CMAC over the entire SMB2 message
3. Comparing the computed signature with the received signature

### 20.2 Encryption Key Derivation

Encryption keys are derived from the session key returned by the authentication mechanism. Implementers MUST ensure proper key derivation and rotation as specified in [MS-SMB2].

### 20.3 Downgrade Protection

The SMB 3.1.1 dialect provides pre-authentication integrity to prevent downgrade attacks. Implementers SHOULD prefer higher dialects when available and MUST validate negotiate responses.

---

## 21. IANA Considerations

### 21.1 Port Numbers

The SAMBA 2 protocol and Samba 3 implementation use the following ports:

| Transport | Port | Protocol |
|-----------|------|----------|
| Direct TCP | 445 | TCP |
| NetBIOS over TCP | 139 | TCP |
| NetBIOS Name Service | 137 | UDP |
| NetBIOS Datagram Service | 138 | UDP |
| QUIC | 443 | UDP |
| SWAT | 901 | TCP |

### 21.2 ALPN Identifier

The ALPN identification sequence for SMB over QUIC is 0x73 0x6D 0x62 ("smb").

---

## 22. References

### 22.1 Normative References

1. [MS-SMB2] Microsoft Corporation, "Server Message Block (SMB) Protocol Versions 2 and 3"
2. [MS-SMBD] Microsoft Corporation, "SMB2 Remote Direct Memory Access (RDMA) Transport Protocol"
3. [MS-CIFS] Microsoft Corporation, "Common Internet File System (CIFS) Protocol"
4. [MS-SMB] Microsoft Corporation, "Server Message Block (SMB) Version 1.0 Protocol"
5. [MS-FSA] Microsoft Corporation, "File System Algorithms"
6. [MS-RRP] Microsoft Corporation, "Windows Remote Registry Protocol"
7. [MS-LSAD] Microsoft Corporation, "Local Security Authority (Domain Policy) Remote Protocol"
8. [MS-SAMR] Microsoft Corporation, "Security Account Manager (SAM) Remote Protocol"
9. [MS-NRPC] Microsoft Corporation, "Netlogon Remote Protocol"
10. RFC 1001, "Protocol Standard for a NetBIOS Service on a TCP/UDP Transport: Concepts and Methods"
11. RFC 1002, "Protocol Standard for a NetBIOS Service on a TCP/UDP Transport: Detailed Specifications"
12. RFC 2119, "Key words for use in RFCs to Indicate Requirement Levels"
13. RFC 2307, "An Approach for Using LDAP as a Network Information Service"
14. RFC 5040, "A Remote Direct Memory Access Protocol Specification"
15. RFC 5041, "Direct Data Placement over Reliable Transports"
16. RFC 9000, "QUIC: A UDP-Based Multiplexed and Secure Transport"
17. X/Open CAE, "Protocols for X/Open PC Interworking: SMB, Version 2"

### 22.2 Informative References

1. Samba Team, "SMB2 in Samba," SDC 2012
2. Samba Team, "What is SMB2?"
3. USENIX, "Server Message Block in the Age of Microsoft Glasnost"
4. SMB2_IMPL_ID Design Specification, "Implementation Identification Negotiate Context"
5. Samba Team, "The Official Samba-3 HOWTO and Reference Guide"

---

## Appendix A: SMB2 Opcode Reference

| Opcode | Name | Direction |
|--------|------|-----------|
| 0x00 | NEGOTIATE | Client → Server |
| 0x01 | SESSION_SETUP | Client → Server |
| 0x02 | LOGOFF | Client → Server |
| 0x03 | TREE_CONNECT | Client → Server |
| 0x04 | TREE_DISCONNECT | Client → Server |
| 0x05 | CREATE | Client → Server |
| 0x06 | CLOSE | Client → Server |
| 0x07 | FLUSH | Client → Server |
| 0x08 | READ | Client → Server |
| 0x09 | WRITE | Client → Server |
| 0x0A | LOCK | Client → Server |
| 0x0B | IOCTL | Client → Server |
| 0x0C | CANCEL | Client → Server |
| 0x0D | KEEPALIVE | Client → Server |
| 0x0E | QUERY_DIRECTORY | Client → Server |
| 0x0F | CHANGE_NOTIFY | Client → Server |
| 0x10 | QUERY_INFO | Client → Server |
| 0x11 | SET_INFO | Client → Server |
| 0x12 | OPLOCK_BREAK | Server → Client |

---

## Appendix B: SMB2 Flags

| Flag | Value | Description |
|------|-------|-------------|
| SMB2_FLAGS_SERVER_TO_REDIR | 0x00000001 | Response from server |
| SMB2_FLAGS_ASYNC_COMMAND | 0x00000002 | Asynchronous operation |
| SMB2_FLAGS_RELATED_OPERATIONS | 0x00000004 | Related compound operation |
| SMB2_FLAGS_SIGNED | 0x00000008 | Message is signed |
| SMB2_FLAGS_PRIORITY_MASK | 0x00000070 | Priority mask |
| SMB2_FLAGS_DFS_OPERATIONS | 0x10000000 | DFS operation |

---

## Appendix C: smb.conf Parameter Reference

This appendix lists the complete set of parameters defined in Samba 3.6.25. Parameters marked **[G]** apply only to the `[global]` section. Parameters marked **[S]** apply only to share sections. Unmarked parameters apply to both.

### C.1 Global and Share Parameters

| Parameter | Type | Default | Section |
|-----------|------|---------|---------|
| `abort shutdown script` | Command | NULL | [G] |
| `add group script` | Command | NULL | [G] |
| `add machine script` | Command | NULL | [G] |
| `add port command` | Command | NULL | [G] |
| `add printer command` | Command | NULL | [G] |
| `add share command` | Command | NULL | [G] |
| `add user script` | Command | NULL | [G] |
| `admin users` | List | NULL | [S] |
| `ads server` | String | NONE | [G] |
| `algorithmic rid base` | Integer | 1000 | [G] |
| `allow hosts` | List | NULL | Both |
| `announce as` | Enum | NT | [G] |
| `announce version` | String | 4.9 | [G] |
| `browseable` | Boolean | Yes | [S] |
| `browse list` | Boolean | Yes | [G] |
| `case sensitive` | Boolean | No | Both |
| `create mask` | Octal | 0744 | [S] |
| `deadtime` | Integer | 0 | [G] |
| `debug level` | Integer | 0 | [G] |
| `delete group script` | Command | NULL | [G] |
| `delete printer command` | Command | NULL | [G] |
| `delete share command` | Command | NULL | [G] |
| `delete user script` | Command | NULL | [G] |
| `directory mask` | Octal | 0755 | [S] |
| `domain logons` | Boolean | No | [G] |
| `domain master` | Boolean | Auto | [G] |
| `encrypt passwords` | Boolean | Yes | [G] |
| `guest account` | String | nobody | [G] |
| `guest ok` | Boolean | No | [S] |
| `guest only` | Boolean | No | [S] |
| `hosts allow` | List | NULL | Both |
| `hosts deny` | List | NULL | Both |
| `idmap backend` | String | tdb | [G] |
| `idmap uid` | Range | 10000–20000 | [G] |
| `idmap gid` | Range | 10000–20000 | [G] |
| `interfaces` | List | All | [G] |
| `bind interfaces only` | Boolean | No | [G] |
| `invalid users` | List | NULL | [S] |
| `kernel oplocks` | Boolean | Yes | [G] |
| `load printers` | Boolean | Yes | [G] |
| `local master` | Boolean | Yes | [G] |
| `lock directory` | Path | /var/lock/samba | [G] |
| `log file` | Path | log.%m | [G] |
| `log level` | Integer | 0 | [G] |
| `logon drive` | String | NULL | [G] |
| `logon home` | String | NULL | [G] |
| `logon path` | String | NULL | [G] |
| `logon script` | String | NULL | [G] |
| `max log size` | Integer | 5000 | [G] |
| `max protocol` | Enum | NT1 | [G] |
| `min protocol` | Enum | LANMAN1 | [G] |
| `netbios name` | String | Hostname | [G] |
| `obey pam restrictions` | Boolean | No | [G] |
| `oplocks` | Boolean | Yes | [S] |
| `os level` | Integer | 20 | [G] |
| `passdb backend` | List | smbpasswd | [G] |
| `path` | Path | NULL | [S] |
| `preferred master` | Boolean | Auto | [G] |
| `printable` | Boolean | No | [S] |
| `print command` | Command | lpr -r -P%p %s | [S] |
| `printing` | Enum | cups | [G] |
| `public` | Boolean | No | [S] |
| `read only` | Boolean | Yes | [S] |
| `security` | Enum | user | [G] |
| `server string` | String | Samba %v | [G] |
| `smb passwd file` | Path | /etc/samba/smbpasswd | [G] |
| `socket options` | List | TCP_NODELAY | [G] |
| `strict locking` | Boolean | No | [S] |
| `username map` | Path | NULL | [G] |
| `valid users` | List | NULL | [S] |
| `veto files` | List | NULL | [S] |
| `vfs objects` | List | NULL | [S] |
| `winbind enum groups` | Boolean | No | [G] |
| `winbind enum users` | Boolean | No | [G] |
| `winbind separator` | String | \ | [G] |
| `winbind uid` | Range | NULL | [G] |
| `winbind gid` | Range | NULL | [G] |
| `workgroup` | String | WORKGROUP | [G] |
| `writeable` | Boolean | No | [S] |

---

## Appendix D: SMB Command Codes (SMB1/CIFS)

| Code | Command | Description |
|------|---------|-------------|
| 0x00 | NEGPROT | Negotiate Protocol |
| 0x01 | SETUPANDX | Session Setup (AndX) |
| 0x02 | TCONANDX | Tree Connect (AndX) |
| 0x03 | TCON | Tree Connect |
| 0x04 | NT_CREATE_ANDX | NT Create File (AndX) |
| 0x05 | NT_TRANSACT | NT Transaction |
| 0x06 | CLOSE | Close File |
| 0x07 | READ | Read File |
| 0x08 | WRITE | Write File |
| 0x09 | LOCK | Lock/Unlock |
| 0x0A | UNLOCK | Unlock |
| 0x0B | CREATE | Create File |
| 0x0C | DELETE | Delete File |
| 0x0D | RENAME | Rename File |
| 0x0E | LOGOFF_ANDX | Logoff (AndX) |
| 0x0F | TDIS | Tree Disconnect |
| 0x10 | OPEN | Open File |
| 0x11 | CHECK_DIRECTORY | Check Directory |
| 0x12 | GET_PRINT_QUEUE | Get Print Queue |
| 0x13 | SET_INFORMATION | Set File Information |
| 0x14 | QUERY_INFORMATION | Query File Information |
| 0x15 | FIND_FIRST2 | Find First (Level 2) |
| 0x16 | FIND_NEXT2 | Find Next (Level 2) |
| 0x17 | FIND_CLOSE2 | Find Close |
| 0x18 | READ_ANDX | Read File (AndX) |
| 0x19 | WRITE_ANDX | Write File (AndX) |
| 0x1A | LOCK_ANDX | Lock (AndX) |
| 0x1B | UNLOCK_ANDX | Unlock (AndX) |
| 0x1C | TRANSACT | Transaction |
| 0x1D | TRANSACT2 | Transaction 2 |
| 0x1E | IOCTL | I/O Control |
| 0x1F | SESSION_SETUP_ANDX | Session Setup (AndX) |
| 0x20 | TREE_CONNECT_ANDX | Tree Connect (AndX) |
| 0x21 | GET_DFS_REFERRAL | Get DFS Referral |
| 0x22 | REPORT_DFS_INCONSISTENCY | Report DFS Inconsistency |
| 0x23 | QUERY_PATH_INFO | Query Path Information |
| 0x24 | SET_PATH_INFO | Set Path Information |
| 0x25 | QUERY_FILE_INFO | Query File Information |
| 0x26 | SET_FILE_INFO | Set File Information |
| 0x27 | FSCTL | File System Control |
| 0x28 | IOCTL2 | I/O Control 2 |
| 0x29 | FIND_NOTIFY_FIRST | Find Notify First |
| 0x2A | FIND_NOTIFY_NEXT | Find Notify Next |
| 0x2B | CANCEL | Cancel |
| 0x2C | KERBOS | Kerberos |
| 0x2D | CHANGE_NOTIFY | Change Notify |
| 0x2E | QUERY_INFO | Query Information |
| 0x2F | SET_INFO | Set Information |
| 0x30 | FSCTL2 | File System Control 2 |
| 0x31 | NOTIFY_CHANGE | Notify Change |
| 0x32 | SHUTDOWN | Shutdown |
| 0x33 | EXTENDED_SECURITY | Extended Security |
| 0x34 | NT_CANCEL | NT Cancel |
| 0x35 | NT_TRANSACT2 | NT Transaction 2 |
| 0x36 | NT_CREATE | NT Create |

---

## Appendix E: Well-Known SIDs and RIDs

| SID / RID | Name | Description |
|-----------|------|-------------|
| `S-1-5-18` | LOCAL_SYSTEM | System account |
| `S-1-5-19` | LOCAL_SERVICE | Local service account |
| `S-1-5-20` | NETWORK_SERVICE | Network service account |
| `S-1-5-32-544` | BUILTIN\Administrators | Built-in administrators group |
| `S-1-5-32-545` | BUILTIN\Users | Built-in users group |
| `S-1-5-32-546` | BUILTIN\Guests | Built-in guests group |
| `S-1-5-32-547` | BUILTIN\Power Users | Power users group |
| `S-1-5-32-548` | BUILTIN\Account Operators | Account operators |
| `S-1-5-32-549` | BUILTIN\Server Operators | Server operators |
| `S-1-5-32-550` | BUILTIN\Print Operators | Print operators |
| `S-1-5-32-551` | BUILTIN\Backup Operators | Backup operators |
| `S-1-5-32-552` | BUILTIN\Replicators | Replicators |
| `RID 500` | Administrator | Built-in administrator account |
| `RID 501` | Guest | Built-in guest account |
| `RID 512` | Domain Admins | Domain administrators |
| `RID 513` | Domain Users | Domain users |
| `RID 514` | Domain Guests | Domain guests |
| `RID 515` | Domain Computers | Domain computer accounts |
| `RID 516` | Domain Controllers | Domain controllers |
| `RID 517` | Cert Publishers | Certificate publishers |
| `RID 518` | Schema Admins | Schema administrators |
| `RID 519` | Enterprise Admins | Enterprise administrators |
| `RID 520` | Group Policy Creator Owners | GPO creators |

---

## Appendix F: Change History

| Version | Date | Changes |
|---------|------|---------|
| 3.0.0 | 2003-09-24 | Initial Samba 3 release. New passdb architecture, idmap, VFS modules, Unicode support, Kerberos/AD integration. |
| 3.0.6 | 2004-08-19 | LDAP schema extension. |
| 3.0.14a | 2005 | Major code refactoring. |
| 3.0.20 | 2006 | Windows 2003 R2 compatibility. |
| 3.0.24 | 2007 | Security fixes. |
| 3.2.0 | 2008-07 | Registry-based configuration introduced. |
| 3.3.0 | 2009-01 | Improved winbind functionality. |
| 3.4.0 | 2009-07 | SMB2 protocol support (experimental). |
| 3.5.0 | 2010-03 | SMB2 stability improvements. |
| 3.6.0 | 2011-08 | SMB2.0 support (excluding durable file handles). |
| 3.6.25 | 2015-02 | Final Samba 3.6 release. |
