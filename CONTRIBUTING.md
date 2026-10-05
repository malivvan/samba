# Contributing to samba

Thanks for your interest! samba is a from-scratch SMB2/SMB3 file server written
in pure Go. Contributions — bug reports, protocol-correctness fixes,
performance work, packaging, docs — are all welcome.

## Ground rules

- **Pure Go only.** No CGO and no `unsafe`. CI enforces both: the module must
  build with `CGO_ENABLED=0`, and a check fails if `unsafe` appears in any
  non-test file. The whole point is a statically linkable, memory-safe server,
  so a change that needs a C library has to be re-thought — not exempted.
- **Linux at runtime.** The transport uses `SO_REUSEPORT`, `inotify`, OFD byte
  range locks and `splice(2)` (through the Go runtime); the package builds and
  the protocol layer unit-tests anywhere, but the server is a Linux server.
- Keep the concurrency model intact unless there is a measured reason not to:
  one goroutine per connection drives the transmit direction, server-initiated
  frames are queued rather than written concurrently, and the only shared locks
  are the session registry, the per-session handle table and the lease table.
- **New wire behaviour needs a test.** Drive `ProcessFrame` and assert on the
  bytes (see `smb2_test.go`), or drive a real socket (see `server_test.go`).
- Run before pushing:
  ```sh
  go build ./...
  go vet ./...
  go test ./...
  go test -race ./...
  ```
- Any change on the wire-parsing hot path should also see a few seconds of
  fuzzing: `go test -run '^$' -fuzz FuzzProcessFrame -fuzztime 30s .`.

## Project layout

| File | Contents |
|---|---|
| `doc.go` | package documentation and the version constant |
| `wire.go` | little-endian wire primitives (Reader/Writer, UTF-16LE) |
| `smb2.go` | SMB2 header codec, compound dispatch, transform header, `ProcessFrame` |
| `handlers.go` | command handlers (negotiate, session setup, tree, create, read/write, dir, info, lock, notify, ioctl, leases) |
| `server.go` | transport: SO_REUSEPORT listeners, per-connection goroutines, zero-copy READ, worker mailboxes |
| `notify.go` | inotify watcher backing CHANGE_NOTIFY |
| `session.go` | cross-connection session registry (multichannel) |
| `lease.go` | file-keyed lease table and cross-worker break mailbox |
| `vfs.go` | filesystem layer: path resolution, handle table, metadata |
| `crypto.go`, `cmac.go`, `ccm.go`, `md4.go` | signing, KDF and AEAD primitives |
| `ntlm.go`, `spnego.go`, `krb5.go` | authentication mechanisms |
| `config.go` | TOML configuration and the resolved server context |
| `status.go`, `log.go` | NTSTATUS codes and logging |
| `netinfo.go` | interface enumeration for multichannel |
| `cmd/samba/` | the command-line entry point |
| `docs/` | architecture, benchmark, testing, tuning and security notes |
| `bench/` | host scripts: benchmark suite, stress/soak, Kerberos e2e, Windows interop |

## Commit style

Conventional commits (`feat:`, `fix:`, `perf:`, `docs:`, `chore:`). One logical
change per commit. Update `CHANGELOG.md` and the relevant `docs/`.

## Security

Do not file public issues for vulnerabilities — see `SECURITY.md`.
