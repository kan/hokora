# hokora

[![CI](https://github.com/kan/hokora/actions/workflows/ci.yml/badge.svg)](https://github.com/kan/hokora/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/kan/hokora/sdk.svg)](https://pkg.go.dev/github.com/kan/hokora/sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**hokora** is a minimal secret-management server for a **single organization**.
It is written in Go and ships as a single, dependency-light binary backed by
SQLite.

Its one goal:

> Let application servers stop holding long-lived secrets in config files.
> Instead of *N* secrets sitting on disk, an app holds **one revocable machine
> credential** and fetches the secrets it is granted, over TLS, into memory.

That is the whole pitch. hokora is deliberately small. Before you adopt it,
read what it **does not** do — that section is longer than the pitch, on
purpose.

---

## What hokora does NOT do

hokora makes narrow, honest claims. It does **not** protect against the
following, and neither do Vault or Infisical — these are inherent to the
problem, not hokora bugs:

- **It does not solve the "secret zero" problem.** An attacker who obtains your
  application's OS user can read that machine's credential (from
  `$CREDENTIALS_DIRECTORY` or the environment) and fetch exactly the secrets
  that machine is granted — or read your process memory directly. hokora shrinks
  *what* leaks (a revocable credential, not the secrets' config file) and gives
  you a revoke button; it does not stop a same-user attacker from reading
  granted secrets.

- **Defense against a compromised application host (T1) is partial.** hokora
  replaces "all secrets on disk forever" with "one credential + only the
  granted secrets, in memory." That is a real reduction, not immunity.

- **`hokora-client run` exposes secrets via `/proc/<pid>/environ`.** The `run`
  subcommand expands secrets into a child process's environment, which a
  same-user attacker can read. It is a **migration aid only**. Go applications
  should import the SDK (`github.com/kan/hokora/sdk`) and keep secrets in
  `[]byte`, never in the environment.

- **Application-server disk leaks are out of scope.** swap, core dumps, and
  kernel crash dumps on the *app* host can spill secrets to disk. hokora cannot
  manage that host; you must (see the operational requirements below). The same
  applies to the hokora host, which hokora *does* harden.

- **`revoke` only stops *future* fetches.** Disabling a machine or deleting a
  grant prevents new reads immediately, but any secret already retrieved is
  already out. After a compromise you must **rotate the affected secrets**
  themselves; revoking is not recovery.

- **No high availability, no clustering, no multi-tenancy.** One organization,
  one node. If you need replication or HA, use Vault, not hokora.

If any of these are dealbreakers for your threat model, hokora is not for you.
The full model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — **read it
before deploying.**

---

## Operational requirements are mandatory

hokora's guarantees depend on host configuration. These are **not optional
hardening** — without them, hokora does not deliver what it claims:

- **`mlockall`** — hokora locks its memory to keep keys out of swap and refuses
  to start if it cannot (`LimitMEMLOCK=infinity` in the systemd unit).
- **core dumps disabled** (`LimitCORE=0` + `systemd-coredump` masked).
- **kdump disabled** — a kernel crash dump writes all of physical memory to
  disk.
- **firewalld** restricting the Machine API port to your application hosts
  (hokora does not implement IP allowlisting — that is the firewall's job).
- **TLS** from a public CA, with certbot running on a **separate host** (the DNS
  API credential must not live on the hokora host).

Full runbook: [docs/OPERATIONS.md](docs/OPERATIONS.md).

---

## Should you use hokora, or SOPS + age?

If you do **not** need a live, revocable credential and a browser UI — if a
small team editing encrypted files in git is enough — then **[SOPS] + [age] is
simpler and has a smaller attack surface.** Reach for it first.

hokora earns its extra moving parts only when you want:

- a **revocable machine credential** instead of distributing secret files,
- a **Web UI** (behind a VPN) for humans to manage secrets and grants,
- an **audit log** of every secret read.

[SOPS]: https://github.com/getsops/sops
[age]: https://github.com/FiloSottile/age

---

## Architecture at a glance

```
                     VPN                          public (firewalled)
  ┌──────────────┐   :8443  ┌───────────────┐  :9443  ┌──────────────┐
  │ operator      │────────▶│  hokora        │◀────────│ app host      │
  │ (browser)     │  Web UI │  (single Go    │ Machine │ hokora-client │
  └──────────────┘         │   binary)      │   API   │  or sdk/      │
                            │                │         └──────────────┘
        root only ─────────▶│ admin unix sock│
        (unseal/seal)       │  SQLite (enc)  │
                            └───────────────┘
```

- **Envelope encryption**: a master key (MK) unwraps a key-encryption key
  (KEK, argon2id) which unwraps a data-encryption key (DEK, AES-256-GCM). The MK
  never touches disk; hokora starts **sealed** and is unsealed by feeding the MK
  over stdin / an HTTP body (never argv or env).
- **Three isolated listeners**: Machine API (mutual-firewalled), Web UI
  (loopback/VPN), and a root-only admin unix socket — each with its own
  `ServeMux`.
- **Two binaries**: `hokora` (the server; links SQLite + argon2) and
  `hokora-client` (app-host client; **standard library only**, ~9 MB vs ~20 MB).
  Go apps skip the client and import the `sdk/` package directly.

Design details: [docs/DESIGN.md](docs/DESIGN.md). Milestones and status:
[docs/ROADMAP.md](docs/ROADMAP.md).

---

## Install

**Linux only.** hokora relies on `mlockall`, unix sockets, and systemd; it is
built and supported for Linux (amd64 / arm64).

Release binaries (recommended):

```
# from the GitHub Releases page: hokora_<version>_linux_<arch>.tar.gz (server)
#                                hokora-client_<version>_linux_<arch>.tar.gz
```

From source (Go 1.26.5+):

```
git clone https://github.com/kan/hokora
cd hokora
make build          # produces ./hokora and ./hokora-client
```

The Go SDK for applications:

```
go get github.com/kan/hokora/sdk
```

---

## Quickstart (local, for evaluation)

`hokora serve` calls `mlockall` and will not start unless it can lock memory, so
local evaluation needs root (or `LimitMEMLOCK`/`ulimit -l unlimited`).

```bash
# 1. initialize — prints the master key (stdout) and initial admin password
#    (stderr) exactly once. Store the master key in a password manager now.
sudo -u hokora hokora init --db /var/lib/hokora/hokora.db

# 2. run the server (starts SEALED). See docs/OPERATIONS.md for the systemd unit.
sudo hokora serve --db /var/lib/hokora/hokora.db --tls-dir /var/lib/hokora/tls/current

# 3. in a browser on the VPN: https://<vpn-ip>:8443/ui/login
#    log in as admin, change the password, then unseal with the master key.

# 4. create a project / environment / item, then a machine and a grant, in the UI.
```

Fetch secrets from an application:

```go
import "github.com/kan/hokora/sdk"

client, _ := hokora.New()            // reads $CREDENTIALS_DIRECTORY/hokora
secrets, _ := client.Fetch(ctx)
db := secrets.MustGetString("DATABASE_URL")
defer secrets.Zero()                 // best effort (cannot beat swap/core dump)
```

or, for non-Go / legacy apps being migrated:

```bash
hokora-client get DATABASE_URL       # one value to stdout (terminal use only)
hokora-client run -- ./legacy-app    # expands secrets into the env — see the
                                     # /proc caveat above; prefer the SDK
```

---

## Status

hokora is a **young, single-maintainer project** built for one organization's
use. Its design went through several rounds of external review, and the code is
tested (including the concurrency invariants that a race detector cannot catch),
but it has not seen broad production exposure. Treat it accordingly, and read
the threat model before trusting it with real secrets.

---

## Documentation

| File | Contents |
|------|----------|
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What is defended, what is not. **The basis for every design decision.** |
| [docs/DESIGN.md](docs/DESIGN.md) | Architecture, data model, crypto, API, concurrency. |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Runbook: systemd, firewalld, TLS, backup/restore, key rotation, incident response. |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Milestones and scope. |
| [AGENTS.md](AGENTS.md) | Instructions and hard rules for AI agents working on this repo. |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Copyright 2026 Kan Fushihara.
