# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/kan/hokora/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kan/hokora/releases/tag/v0.1.0
