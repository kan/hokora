# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **`go.mod` now declares `go 1.26` with a separate `toolchain go1.26.5`.**
  Since Go 1.21 a dependency's `go` directive is a *minimum* imposed on the
  consumer, so declaring a patch version (`go 1.26.5`) made `go mod tidy`
  rewrite a consumer's own `go 1.26` line to `go 1.26.5`, which then propagated
  further downstream. Importing `github.com/kan/hokora/sdk` no longer does that.
  A dependency's `toolchain` directive is ignored downstream, so hokora itself
  still builds and is scanned with go1.26.5 at no cost to consumers. A new
  `make toolchain-check` (wired into `make all` and CI) fails when the running
  toolchain differs from the declared one, so `GOTOOLCHAIN=local` with an older
  1.26.x cannot silently satisfy the relaxed `go` line.
- **The SDK is now its own module (`github.com/kan/hokora/sdk`).** Importing it
  used to make the application resolve the server's dependencies (SQLite driver
  and friends) and accept the server's Go requirement. It now contributes
  exactly one module to a consumer's build list and requires only **Go 1.24**.
  `go get github.com/kan/hokora/sdk` is unchanged, but SDK releases are tagged
  `sdk/vX.Y.Z`. The server module builds the SDK from the tree
  (`replace ... => ./sdk`), so `go install github.com/kan/hokora@version` is no
  longer supported; install from Releases or `git clone` + `make build`.
- **Development tools moved to a separate `tools/` module.** `golangci-lint` and
  `govulncheck` are not linked into any binary, but declaring them with `tool`
  directives in the root `go.mod` listed 200+ indirect requirements there, and
  those propagated into the module graph of anything importing the SDK. A
  consumer that imports only `github.com/kan/hokora/sdk` now sees 15 modules
  instead of 225. Nothing about the released binaries changes.

## [0.2.0] - 2026-07-22

### Added

- **`hokora backup`**: online, ciphertext-only backups via SQLite `VACUUM INTO`.
  It runs while the server is live and even while sealed (it never touches the
  vault, DEK, or master key), so it needs no stop/unseal and writes a single
  self-contained file (no `-wal` / `-shm` to miss). The destination is created
  `0600` before the copy so the ciphertext is never briefly world-readable, is
  re-opened read-only to check its schema version, and refuses to overwrite an
  existing file. This is the online replacement for the offline stop-and-copy
  procedure and the primary way to seed a cold standby; see
  [docs/OPERATIONS.md](docs/OPERATIONS.md) §9. Backups are deliberately not
  audit-logged (the operation cannot run inside a transaction, and any principal
  who can run it can already copy the ciphertext database directly).

## [0.1.0] - 2026-07-21

Initial release. A minimal secret-management server for a single organization
(Linux, single binary, SQLite). See [README](README.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what it does and, importantly,
what it does not.

### Added

- **Envelope encryption**: master key → KEK (argon2id) → DEK (AES-256-GCM), with
  fixed-width AAD and range checks. The master key never touches disk.
- **Seal / unseal state machine** with the concurrency invariants C1–C10
  (seal barrier, token issuance under read lock, revocation under write lock,
  login password re-read, rotate-master serialization, fixed lock ordering).
- **`mlockall`** at startup (refuses to start if it cannot lock memory).
- **Machine API** (`/v1/auth/token`, `/v1/secrets`, `/v1/secrets/{key}`):
  SHA-256 credential verification (not argon2 on the unauthenticated path),
  short-lived tokens, per-request re-authorization, IP-first rate limiting.
- **Web UI** (VPN/loopback): projects, environments, items, machines, grants,
  users, and audit-log browsing; `__Host-` session cookies with hashed storage,
  CSRF derived from the session token, Fetch-Metadata/Origin login checks,
  strict CSP, no response compression, and bfcache handling for plaintext pages.
- **Audit log** for every secret access (reads and failures), append-only, with
  immutable IDs and fail-closed / fail-open semantics.
- **Three isolated listeners** — Machine API, Web UI, and a root-only admin unix
  socket — each with its own `ServeMux`; TLS certificate reload on SIGHUP that
  keeps the old certificate on failure.
- **`master.rotate`** (generate the new key separately with `gen-key`).
- **Go SDK** (`github.com/kan/hokora/sdk`): standard-library only, keeps secrets
  in memory, no cache, `https`-only, no insecure-skip-verify.
- **`hokora-client`** binary (`get` / `run`) for non-Go and legacy apps —
  standard-library only, so it does not link the server's dependencies.
- **Operations runbook** (`docs/OPERATIONS.md`): systemd units, swap / core dump
  / kdump, firewalld, TLS via certbot on a separate host, backup / restore, key
  rotation, and incident response.
- **Release tooling**: reproducible Linux amd64/arm64 builds via GoReleaser.

[Unreleased]: https://github.com/kan/hokora/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kan/hokora/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kan/hokora/releases/tag/v0.1.0
