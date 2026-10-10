# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **The declared toolchain is now `go1.26.6`** (was `go1.26.5`). Go 1.26.6 fixes
  six standard-library vulnerabilities that hokora's own code reaches —
  GO-2026-6218 (`net/url`), GO-2026-6091 (`html/template`), GO-2026-6090
  (`crypto/tls`), GO-2026-6089 and GO-2026-5026 (`net/http`), and GO-2026-5972
  (`encoding/asn1`). The scheduled `vuln` workflow reported them on 2026-08-17
  without anyone changing the repository, which is what that schedule exists
  for. CI installs the version named by the `toolchain` line, so the declaration
  is what decides which compiler builds and scans the release.
- **The declared toolchain is now `go1.27.2`** (was `go1.26.6`), and the root
  module's `go` line is now `1.27`. Twelve more standard-library
  vulnerabilities that hokora's own code reaches were published against
  go1.26.6 — in `net/http`, `net/textproto`, `crypto/tls` and `html/template`
  (GO-2026-6599 through GO-2026-6617), all fixed in go1.26.9 and in go1.27.2.
  Building the server from source now needs Go 1.27; **the SDK module still
  declares `go 1.24`**, so applications importing `sdk` are unaffected.

### Upgrade notes

- **This release changes the database schema (schema v4). Run
  `hokora init --migrate-only` before starting the new binary.** `hokora serve`
  refuses a database whose schema version does not match (`database schema
  version is 1, want 4`). On an existing database `init` applies only the
  pending migration and prints no master key and no password. The new
  `--migrate-only` flag makes it fail instead of creating a fresh database when
  the path is wrong. Take a backup with the old binary first — the new binary
  cannot back up an unmigrated database, and once migrated, the database cannot
  be opened by an older binary. The full procedure is in `docs/OPERATIONS.md`
  §1.3.

### Added

- **A user manual, published with GitHub Pages at
  <https://kan.github.io/hokora/>** (#23). It is written in Japanese and covers
  a glossary (including how the English terms map to the Web UI's Japanese
  labels), a walkthrough of the Web UI, how applications fetch secrets (SDK and
  `hokora-client`), and a command reference. The existing design and operations
  documents are published on the same site. The sources are `docs/index.md` and
  `docs/manual/`; procedures stay in `docs/OPERATIONS.md` and the manual links
  to them. `make docs-check` (part of `make all` and CI) rejects Liquid syntax
  in `docs/*.md`, which Jekyll would otherwise silently drop from the published
  page.
- **The per-credential limit on `POST /v1/auth/token` can be raised for one
  machine** (#28). The limit was a constant: 10 authentications a minute per
  `client_id`, successes included. An application that authenticates every time
  it starts — a script run from cron or once per request, which cannot keep a
  token — exceeds that as a matter of course, and each rejected start failed
  (and wrote a `rate_limited` audit row). The Machines page now has a "認証の上限"
  column: an admin sets the limit for that machine, from 10 (the default) to 30
  a minute. The change is audited as `machine.set_auth_rate`; raising the limit
  is refused when the audit row cannot be written, lowering it is not, and
  submitting the current value writes nothing.
  **The per-source-IP limit (30 a minute) is unchanged and is not configurable**,
  so one host still cannot authenticate more than 30 times a minute whatever
  the machines on it are set to. The setting is per machine, not per project or
  environment: authentication happens before the server knows which environment
  will be read. A raised limit can be observed without the secret by anyone who
  knows the `client_id` (`docs/THREAT_MODEL.md`, N7).
- **A 429 from `POST /v1/auth/token` now carries `Retry-After`** — the number of
  seconds until the window that rejected the request ends. **Only callers that
  speak HTTP to the server themselves can read it.** The SDK and `hokora-client`
  still report a 429 as a plain "rate limited" error, without the wait, and do
  not retry.
- **`hokora audit-prune --keep-days N` deletes routine audit rows older than N
  days** (#27). Until now the audit log could only grow: a client that fetches
  every key each time it starts, run every minute, adds over 30,000 rows a day,
  and on one production database the audit log had become nearly the whole
  database within 80 days. What is pruned is deliberately narrow — **only
  successful machine reads (`secret.read`) and successful machine logins
  (`auth.machine`)**, which were 99.9% of the rows measured. Failures, every
  human action (reveals, writes, credential rotation, grants, unseal, logins)
  and the prune records themselves are kept regardless of age.
  - **Nothing is pruned by default.** `--keep-days` is required and must be at
    least 30; how long to keep is an operational decision. `--dry-run` counts
    without changing anything. Run it from a timer, as the user that owns the
    database file (it refuses to run as anyone else, root included); hokora
    never prunes on its own (`docs/OPERATIONS.md` §12.3).
  - **There is still no way to delete audit rows from the Web UI or the API.**
    The command works on the database file, so only an OS user who can already
    rewrite that file can run it. Each run records itself as `audit.prune`
    (what cutoff, how many rows) before it deletes anything, and stops if that
    record cannot be written.
  - **The trade-off:** for the pruned period you can no longer check whether a
    secret was read. Keep at least as long as a compromise could go unnoticed;
    rows pruned from the database remain in backups taken earlier
    (`docs/THREAT_MODEL.md` §10.7, R17).
  - The database file does not shrink; freed pages are reused, so with regular
    pruning the file levels off at the size of the retained period.

### Changed

- **The audit log screen folds a bulk fetch into one line, and can be filtered
  and paged** (#22). A client that fetches every key used to add one line per
  key on every run, pushing logins, reveals and credential changes off the
  screen. One call is now one line; opening it lists the keys that were read
  (the first 50 inline, with a link to a page that lists all of them).
  The screen can be filtered by period, actor, action, result and target
  environment (disabled machines and deleted environments included), and paged
  50 / 100 / 200 at a time instead of showing only the latest 200 rows. Nothing
  about what is recorded changes: there is still one audit row per key.
- **The audit log's indexes are rebuilt around the queries that use them, and
  each audit write updates fewer of them.** On a production database (80 days,
  650,000 rows) the four original indexes, each covering every row, were
  together as large as the table itself. The audit list now reads small indexes
  that hold only the rows it shows, so the full-table indexes on time and on
  machine are dropped, and the per-user and per-key indexes now cover only the
  rows they apply to. On production-shaped data this makes a compacted database
  about a quarter smaller (123 MB → 94 MB for 670,000 rows; the table itself,
  73 MB, is unchanged). Looking up who read a given key still has its index.
  **If you query the database directly, read `docs/OPERATIONS.md` §12.2:** a
  bare `WHERE at >= …` over all rows no longer has an index, and the section
  shows the form that does. Dropping an index does not shrink the database file
  (freed pages are reused); a `hokora backup` copy is compacted and shrinks at
  once.
- **Audit rows written by one bulk fetch are now marked as one batch**
  (`audit_logs.batch_id`, #22). A bulk fetch still writes one row per key; the
  mark only lets the audit screen show the call as a single line. Rows written
  before the upgrade are left exactly as they are — the audit log stays
  append-only, and guessing which old rows belonged to one call is not
  recorded as fact — so they keep appearing one per key. The migration also
  adds the indexes the audit list is read through.
- **Web UI terminology: the machine entity is now labelled 「マシン」** (was
  「サーバー」, and 「アプリ」 before 0.4.0), matching the internal name
  `machine` (#24). 「サーバー」 in the Web UI now refers only to hokora itself
  ("サーバーは sealed です"). The header, the machine and environment screens,
  the error messages, and the glossary in the README and `docs/OPERATIONS.md`
  all use the new label. The `machine` term is unchanged in the schema, audit
  actions, API, and SDK.
- **The audit log screen's `actor` and `action` column headers are now
  「実行者」 and 「操作」** (#25), like the other columns. The recorded values
  (`user:1`, `secret.reveal`, …) are unchanged.
- **The Web UI's top bar and table headers now stay in place while scrolling**
  (#26), so the column names of a long audit log or key list remain visible.
  CSS only (`position: sticky`); no JavaScript was added.
- **`modernc.org/sqlite` 1.54.0 → 1.60.1** (with `modernc.org/libc`,
  `modernc.org/memory` and `github.com/mattn/go-isatty`). No hokora code
  changes; the DSN and PRAGMA handling is unaffected.
- **`golang.org/x/crypto` 0.54.0 → 0.57.0** and **`golang.org/x/sys`
  0.47.0 → 0.49.0**. hokora uses only argon2 and `mlockall` from them; no code
  changes.
- **A scheduled check now fails when the declared Go version falls behind the
  latest stable release** (`make toolchain-latest`, run weekly by the new
  `toolchain` workflow). Dependabot does not raise the `toolchain` line, so
  until now a stale declaration surfaced only once a vulnerability was
  published against it. Dependabot is also configured for `tools/go.mod` now;
  it had been outside the configured directory since the tools were split into
  their own module, and golangci-lint (2.12.2 → 2.14.0) and govulncheck
  (1.6.0 → 1.8.0) had gone stale.

## [0.4.0] - 2026-08-03

### Added

- **`hokora-client bulk`** prints every granted secret as one JSON object
  (`{"KEY":"value",...}` plus a newline, keys sorted) to stdout. It exists for
  applications that cannot use the SDK and read their configuration from a
  script — a Perl `config/base.pl`, for instance, can pipe it through
  `open my $fh, '-|', 'hokora-client', 'bulk'` instead of calling
  `hokora-client get` once per key, which authenticated and made a round trip
  every time. It takes no key arguments: the server's bulk endpoint reads and
  audits every granted key regardless, so filtering client-side would suggest a
  reduction in exposure that does not exist. A failure writes nothing to stdout
  and exits non-zero, so a caller that checks the exit status cannot start with
  a silently empty configuration. See `docs/OPERATIONS.md` §8.4 for the caveats
  — coarser audit granularity than `get`, and no defence against T1-a.

- **Create a server directly from an environment page.** The environment view
  now has a form that creates a machine and grants it access to that
  environment in a single transaction, showing the credential once. Previously
  this took two separate steps (create the machine, then add a grant).

### Changed

- **The audit log view resolves actors and targets to names.** Rows are still
  recorded with immutable IDs only, so the view now joins the current
  `users` / `machines` names and renders them as `alice (user:1)`. The bare
  identifier stays visible because names are neither unique nor immutable.
  Targets are resolved the same way: `machine.*` / `user.*` / `grant.delete`
  record only IDs, so those rows previously showed an empty 対象 column.
- **Web UI terminology.** The machine entity is now labelled 「サーバー」 (was
  「アプリ」, which operators found ambiguous) and a grant is labelled
  「アクセス権」 throughout the Web UI. The `machine` / `grant` terms are
  unchanged in the schema, audit actions, API, and SDK.
- **A machine name is now required, and the list no longer shows `client_id`.**
  The `client_id` is shown once — with the secret — at creation and rotation,
  so the list identifies a machine by its name instead. The name is validated
  server-side (non-empty, no control characters, ≤ 200 bytes).
- **Each Web UI screen now explains its concepts** — a サーバー is a Web system
  等 that fetches secrets, アクセス権 grants access to an environment's secrets,
  and what a credential is.
- **Docs: added a terminology glossary** (README, `docs/OPERATIONS.md`) mapping
  the English technical terms — which the code, API, and docs keep — to the
  Japanese Web UI labels (machine → サーバー, grant → アクセス権), so the UI
  wording change does not diverge from the runbook.

## [0.3.0] - 2026-07-23

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
  consumer that imports only `github.com/kan/hokora/sdk` went from 225 modules
  to 15 with this change alone, and to 1 once the SDK became its own module
  (above). Nothing about the released binaries changes.

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

[Unreleased]: https://github.com/kan/hokora/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/kan/hokora/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kan/hokora/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kan/hokora/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kan/hokora/releases/tag/v0.1.0
