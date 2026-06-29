# Security Policy

`hush` holds secrets. Take reports seriously and so do we.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/jaenster/hush/security/advisories/new).

If that is unavailable, open an issue titled "security contact request" with no
details and we will arrange a private channel.

Please include, where you can:

- the version / commit you tested,
- the key provider in use (`--keychain`, `--touch-id`, `--secure-enclave`, `--ephemeral`),
- a description of the impact and a minimal reproduction.

We aim to acknowledge within a few days and to keep you updated through to a fix.

## Scope

In scope:

- the daemon (`hushd`) and CLI (`hush`),
- the wire protocol and socket permissions,
- the encrypted store, key handling, and memory hygiene (`mlock`, secure-zero),
- provider/federation resolution.

Out of scope:

- vulnerabilities in third-party provider CLIs (`op`, `aws`, `vault`, …) themselves,
- an attacker who already has root or your unlocked login session on the machine —
  `hush` is a local-trust tool and does not defend against a compromised local account.

## Known design boundaries

These are documented trade-offs, not vulnerabilities (see
[docs/security.md](docs/security.md)):

- **Reboot-safe, not restore-safe.** The data key is device-bound; moving machines
  means re-setup, not recovery.
- **Local-only.** The socket is `0600` and user-owned; there is no network surface.
- Touch ID / Secure Enclave providers require a code-signed build; the default
  `--keychain` provider is the one verified in CI.
