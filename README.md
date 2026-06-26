# hush

A macOS-local secrets daemon that replaces `.env` files — think *ssh-agent, but for
environment variables*. Secrets live encrypted on disk and in `mlock`'d memory; a
small CLI talks to a background daemon over a `0600` unix domain socket.

> **Status: early MVP.** The daemon, CLI, wire protocol, encrypted store, memory
> hygiene, and Keychain-backed key storage are implemented and working. Secrets
> survive restarts and reboots. Touch ID gating is the next step — see
> [Limitations](#limitations).

## Why

`.env` files put plaintext secrets on disk and in git history, hand every process the
whole file, and have no audit trail or rotation story. `hush` keeps secrets encrypted
at rest, in locked (non-swappable) memory while live, and behind a single daemon you
can later gate with Touch ID.

## Build

Requires [Zig 0.16](https://ziglang.org/) and [libsodium](https://libsodium.org/)
(`brew install libsodium`).

```sh
zig build            # builds hushd + hush into zig-out/bin
zig build test       # runs the unit tests
```

## Usage

```sh
hushd &                              # start the daemon
hush set dev API_KEY s3cr3t          # store a secret
hush get dev API_KEY                 # -> s3cr3t
hush ls  dev                         # list keys in an env
hush del dev API_KEY                 # remove one
hush ping                            # health check
```

Secrets are organized as `(env, key) -> value`, so `dev`, `tst` and `prod` are kept
separate.

## Architecture

```
hush (CLI)  ──unix socket 0600──►  hushd (daemon)
                                     ├─ mlock'd in-memory store
                                     └─ vault.bin  (XChaCha20-Poly1305 ciphertext)
```

Everything lives under `~/Library/Application Support/hush/` (`hushd.sock`,
`vault.bin`), created `0700`.

Source layout (`src/`):

| file | role |
|-|-|
| `crypto.zig` | XChaCha20-Poly1305 seal/open, `mlock` + secure-zero (libsodium) |
| `protocol.zig` | pure encode/decode of the wire messages |
| `transport.zig` | length-prefixed framing over the socket |
| `store.zig` | `mlock`'d map + atomic encrypted-file persistence |
| `paths.zig` | filesystem locations |
| `daemon/` | `hushd`, `key_provider.zig` (seam), `keychain.zig` (Security.framework) |
| `cli/` | `hush` |

## Wire protocol

Deliberately trivial so SDKs in any language are a few dozen lines — binary, not JSON,
which also keeps secret bytes out of parse buffers. All integers little-endian.

```
frame             = u32_le len | payload
request payload   = u8 op | field*
response payload  = u8 status | field*
field             = u16_le len | bytes
```

`op`: ping=0, set=1, get=2, del=3, list=4.
`status`: ok=0, err=1, not_found=2.

## Security model

- **Encrypted at rest.** The vault is XChaCha20-Poly1305 ciphertext. The data key is
  held in the login Keychain as `…WhenUnlockedThisDeviceOnly` — never written to disk
  in plaintext and never synced off the device. Disk theft yields useless bytes.
- **No swap.** Secret values are held in `mlock`'d memory and zeroed on overwrite,
  delete and shutdown. Request/response buffers carrying secrets are wiped after use.
- **Reboot-safe, not restore-safe** (by design): the design binds the data key to the
  device. Moving to a new machine means re-setup, not recovery.
- **Local-only.** The socket is `0600` and owned by your user; there is no network
  surface.

## Limitations

This is an MVP. Notably:

- **No Touch ID gating yet.** The data key lives in the Keychain and is released
  whenever the device is unlocked; there is no per-access biometric approval. The next
  milestone wraps the data key with a Secure Enclave key under
  `kSecAccessControlUserPresence`. (`hushd --ephemeral` opts into a throwaway in-memory
  key that survives nothing — handy for tests.)
- **Rebuilding `hushd` may prompt once.** The Keychain ACL is bound to the binary's
  code identity, so a fresh build will trigger a one-time "hushd wants to use a key"
  prompt on the next key read — click *Always Allow*. A signed release build has a
  stable identity and won't.
- Single client served at a time (sequential accept).
- No `hush run` wrapper, manifest, audit log or menubar UI yet.

## Roadmap

1. ✅ Daemon + CLI + socket + `mlock` store + encrypted file
2. ✅ Keychain-backed data key (reboot-safe) — *next:* Secure Enclave + Touch ID
3. Audit log + rotation
4. `.vault.toml` manifest (least-privilege, replaces `.env.example`)
5. `hush run --env=<e> -- <cmd>` wrapper (inject at `execve`)
6. Provider federation (1Password / Keeper references)
7. Menubar UI
