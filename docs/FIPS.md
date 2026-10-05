# FIPS 140-3 mode

Go 1.24 and newer ship a **native FIPS 140-3 validated cryptographic module**.
This server has no OpenSSL (and no CGO) — instead it can route the standard
library primitives it uses through that module, which is the natural FIPS story
for a Go program.

## Enabling it

FIPS mode is a build of Go plus a runtime setting, not a server flag:

```sh
GOFIPS140=latest go build -trimpath -o samba ./cmd
GODEBUG=fips140=on ./samba --config /etc/samba/samba.toml
```

With `GODEBUG=fips140=on` the module refuses to start the non-approved
algorithms it would otherwise use, so a misconfiguration fails loudly instead of
silently running in a non-FIPS mode.

## What FIPS mode covers here

| Primitive | Where it comes from | In FIPS mode |
|---|---|---|
| AES-GCM (SMB3 sealing) | `crypto/cipher` (GCM) over `crypto/aes` | Go's validated module |
| AES-CBC (CMAC's block cipher) | `crypto/aes` | Go's validated module |
| HMAC-SHA256, SHA-512 | `crypto/hmac`, `crypto/sha256`, `crypto/sha512` | Go's validated module |
| AES-CMAC (SMB3 signing) | implemented in `cmac.go` over `crypto/aes` | the block cipher is approved; the CMAC construction is ours |
| SP800-108 KDF | implemented in `crypto.go` over HMAC-SHA256 | the PRF is approved; the KDF construction is ours |
| AES-CCM (SMB3 sealing, optional) | implemented in `ccm.go` over `crypto/aes` | the block cipher is approved; the CCM construction is ours |

## What it does **not** cover

- **NTLM.** The NTLM path needs MD4 (the NT hash), MD5 (HMAC-MD5) and RC4 — none
  of which are FIPS-approved. That is the whole authentication surface: Kerberos
  was removed from this server, and `allow_guest = false` is the only way to
  keep an unapproved token out. A FIPS deployment should therefore treat the
  NTLM logon path as outside its boundary.
- **The constructions implemented in this module.** `cmac.go`, `ccm.go` and the
  KDF in `crypto.go` are validated against their RFC test vectors (RFC 4493,
  RFC 3610, SP800-108) and are exercised by the fuzz targets, but they are not
  themselves a validated module. Only the underlying AES and SHA-2
  implementations are.

If you need a fully validated end-to-end stack, validate that claim against your
own FIPS boundary: the honest statement is "the AES and SHA-2 primitives come
from Go's FIPS 140-3 module; the SMB-specific constructions are implemented
here and test-vector-validated".
