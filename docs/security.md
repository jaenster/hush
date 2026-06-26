# Security model

hush is a local, single-user secrets daemon. Its threat model is a laptop that
may be lost, stolen, or have its disk imaged — not a hardened multi-tenant host.

## Guarantees

- **Encrypted at rest.** The vault is XChaCha20-Poly1305 ciphertext (libsodium).
  The data key is held in the login Keychain
  (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) — never written to disk in
  plaintext by hush, never synced off the device. Disk theft yields useless
  bytes.
- **No swap.** Secret values live in `mlock`'d memory and are zeroed on
  overwrite, delete, and shutdown. Request/response buffers that carry secrets
  are wiped after use.
- **Referenced secrets never persist.** A value like `op://…` stores only the
  reference; the real secret is fetched live from the provider and is never
  written to hush's disk. See [providers.md](providers.md).
- **Local only.** The socket is `0600`, owned by your user. There is no network
  surface.
- **Least exposure on use.** `hush -- <cmd>` puts secrets only in the child
  process's environment; they vanish when it exits.

## Touch ID

Optional providers gate the data key behind biometric approval on every unlock:

- `--touch-id` — Keychain item under a `kSecAccessControlUserPresence` access
  control.
- `--secure-enclave` — data key wrapped by a non-extractable Secure Enclave key
  with the same access control.

Both require a code-signed build with a keychain entitlement (macOS rejects the
data-protection keychain / Secure Enclave from unsigned binaries). See
[key-providers.md](key-providers.md).

## Non-guarantees / known limits

- **Reboot-safe, not restore-safe** (by design): the data key is device-bound.
  Moving to a new machine means re-setup, not recovery.
- **cwd scoping is organizational, not a boundary.** A directory's "identity" is
  spoofable (`chdir`), so it organizes access; it is not a security control. The
  real gate is the (optional) Touch ID approval.
- **The daemon trusts local processes.** Any process running as you can talk to
  the socket. A stalled client can also wedge the daemon (it serves one
  connection at a time) — see the README limitations.
- **`eval "$(hush env)"`** loads secrets into your shell, where they persist and
  leak into every child process. Prefer `hush -- <cmd>`.
- **Provider CLIs run in the daemon's environment.** Whoever can start `hushd`
  controls how `op`/`ksm` are invoked.

## Reporting

This is early-stage software. Do not use it as the sole protection for
high-value production secrets yet.
