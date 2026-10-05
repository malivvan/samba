# Kerberos authentication

The server accepts Kerberos through SPNEGO (`sec=krb5` on Linux, "Kerberos" on
Windows), in pure Go: the AP-REQ is validated against a keytab, the ticket's
session key is used to decrypt the authenticator, clock skew and replays are
rejected, and the resulting Kerberos **sub-session key** becomes the SMB session
key that signing and encryption keys are derived from. No system GSS library
and no CGO are involved.

## Configuration

```toml
auth = "both"          # "ntlm", "kerberos" or "both" (Kerberos preferred)

[kerberos]
enabled = true
keytab = "/etc/krb5.keytab"        # default: $KRB5_KTNAME, then /etc/krb5.keytab
spn = "cifs/fileserver.example.com"  # default: cifs/<server_name>
# realm = "EXAMPLE.COM"            # parsed; the realm actually comes from the ticket
```

`auth = "kerberos"` makes the server advertise *only* Kerberos in the NEGOTIATE
SPNEGO hint, so a client offering NTLM is refused with
`STATUS_NOT_SUPPORTED` instead of silently falling back. With `both`, Kerberos
is advertised first and NTLM is the fallback.

## Keytab setup

The server needs a service principal for its SPN, in the keytab the config
points at:

```sh
# On the KDC (MIT krb5 example)
kadmin.local -q "addprinc -randkey cifs/fileserver.example.com"
kadmin.local -q "ktadd -k /etc/krb5.keytab cifs/fileserver.example.com"
```

Notes:

- The SPN defaults to `cifs/<server_name>`; `server_name` defaults to `SAMBA`,
  so a real deployment should set both.
- The client must be able to resolve the server's name and get a ticket for
  exactly this SPN. `sec=krb5` with a bare IP address will not work — Kerberos
  is name-based.
- Keytab entries are enctype-specific. The acceptor supports the standard
  AES enctypes (aes256-cts-hmac-sha1-96, aes128-cts-hmac-sha1-96) and
  RC4-HMAC, which is what Active Directory arrangements usually need.
- MIT keytabs store several enctypes per principal; the acceptor picks the one
  matching the ticket's enctype.

## Client

```sh
kinit alice@EXAMPLE.COM
mount -t cifs //fileserver.example.com/data /mnt -o sec=krb5,vers=3.1.1
# with signing enforced and encryption on
mount -t cifs //fileserver.example.com/data /mnt -o sec=krb5,vers=3.1.1,seal
```

Windows: map the share with "Connect using different credentials" left off (the
logged-on user's ticket is used), or `net use \\fileserver\data /user:alice`.

## What is supported

- **One leg.** A complete AP-REQ (what cifs.ko and Windows send in a single
  SESSION_SETUP) is accepted. A multi-leg exchange is logged and rejected; SMB
  Kerberos does not need mutual authentication, so an AP-REP is not required.
- **SPNEGO and raw tokens.** Both a SPNEGO-wrapped `NegTokenInit` carrying a
  Kerberos `mechToken` and a bare GSS initial-context token are unwrapped and
  accepted.
- **Replay protection.** A process-wide replay cache keyed by client, with
  entries expiring after the clock-skew window.
- **The sub-session key is used for SMB.** If a client omits the authenticator
  subkey, the ticket's session key is used instead.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `LOGON_FAILURE` and "acceptor init failed" in the log | The keytab is missing, unreadable, or has no entry for the SPN. Check with `klist -k /etc/krb5.keytab`. |
| `TIME_DIFFERENCE_AT_DC` | Clock skew between client, server and KDC beyond the allowed window. Run a time sync on all three. |
| `NOT_SUPPORTED` | The client offered NTLM while `auth = "kerberos"`, or sent a token for a mechanism meanwhile disabled. |
| Mount fails with "no such file or directory" for the share | The SPN does not match the name the client used, or the client has no ticket for it. |
| "multi-leg exchange is not supported" | A non-SMB GSS client (or an unusual one) is doing mutual authentication. SMB clients should not. |

Raise `log_level = 2` to see the AP-REQ validation failure reason.
