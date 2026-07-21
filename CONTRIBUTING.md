# Contributing to hokora

Thanks for your interest. hokora is a small, security-focused, single-maintainer
project, so a few things are stricter than usual.

## Before you start

- **Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) first.** Every design
  decision derives from it. A change that adds a defense hokora does not claim,
  or that expands scope, will be declined unless the threat model is revised
  first.
- **Scope is intentionally narrow.** See "実装しないもの" in
  [AGENTS.md](AGENTS.md) (no multi-tenancy, no auto-rotation, no HA, no
  `hokora export`, etc.). Propose scope changes as an issue before writing code.
- **[AGENTS.md](AGENTS.md) contains hard rules** (crypto, master-key handling,
  audit, network boundaries, concurrency). A change that violates them is
  rejected even if it works. Skim it before touching `crypto.go`, `keyring.go`,
  `auth.go`, `session.go`, `audit.go`, or `server.go`.

## Development

Requirements: Go 1.26.5+ (the version in `go.mod` is authoritative). Linux for
running the server (`mlockall`); tests run anywhere.

```bash
make all        # fmt-check → vet → lint → test (-race) → build. Same as CI.
make vuln       # govulncheck — run this when you add or update a dependency.
```

Running the server locally needs root or a raised `LimitMEMLOCK` (see
[docs/OPERATIONS.md](docs/OPERATIONS.md) §0), because `hokora serve` refuses to
start if it cannot lock memory.

## Expectations for a change

- **Tests are written with the code**, not after. Concurrency invariants
  (seal/unseal races, token/credential revocation) need *explicit* tests — the
  race detector does not catch them.
- **No new runtime dependencies** without discussion. The server's allowed
  third-party deps are `modernc.org/sqlite`, `golang.org/x/crypto`, and
  `golang.org/x/sys`. The `sdk/` package and the `hokora-client` binary must
  stay **standard-library only** (enforced by `sdk_deps_test.go`).
- **`gofmt` / `goimports` clean, `golangci-lint` passing.** Fix the code rather
  than suppressing a lint; `//nolint` needs a reason in a comment.
- **Commit messages may be in Japanese or English.** Explain the *why*.
- Do not commit secrets, keys, or database files (`.gitignore` guards the common
  cases).

## Reporting security issues

Do **not** open a public issue for a vulnerability. See
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
