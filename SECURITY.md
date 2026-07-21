# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**, not through public issues.

Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository
(<https://github.com/kan/hokora/security/advisories/new>).

Include what you need to reproduce: affected version/commit, configuration, and
a proof of concept if you have one. You will get an acknowledgement; because
hokora is maintained by a single person, please allow reasonable time for a fix
before any public disclosure.

## What is in scope

hokora's guarantees are defined by [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
A report is in scope if it shows hokora failing to deliver a defense it
**claims** — for example:

- a way to read secrets or the master key without the required credential,
- a bypass of the network/mux boundaries (Machine API vs Web UI vs admin socket),
- a break in the crypto (nonce reuse, missing AAD checks, weak comparison),
- a concurrency flaw that lets a revoked/expired credential still work,
- an audit-log omission for a secret access (read or failure),
- secrets leaking into logs, error messages, or list responses.

## What is NOT in scope

The following are **documented non-defenses**, not vulnerabilities (see the
threat model and the README's "What hokora does NOT do"):

- The "secret zero" problem: an attacker with your application's OS user can
  fetch the secrets that machine is granted. This is inherent to Vault,
  Infisical, and hokora alike.
- Secret exposure via `hokora-client run` / `/proc/<pid>/environ` — the `run`
  subcommand is a migration aid and says so.
- Secrets reaching disk through swap, core dumps, or kdump on the **application**
  host (hokora does not manage that host).
- `revoke` not un-leaking already-fetched secrets.

If you are unsure whether something is in scope, report it privately anyway and
say so.
