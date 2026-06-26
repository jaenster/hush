# hush

A macOS-local secrets daemon that replaces `.env` files — think *ssh-agent, but for
environment variables*. Secrets live encrypted on disk and in `mlock`'d memory; a
small CLI talks to a background daemon over a `0600` unix domain socket.

> **Status: early MVP.** The daemon, CLI, wire protocol, encrypted store, memory
> hygiene, and Keychain-backed key storage are implemented and working. Secrets
> survive restarts and reboots. Touch ID gating is implemented but needs a
> code-signed build — see [Key providers](#key-providers).

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
| `daemon/` | `hushd`, `key_provider.zig` (seam), `keychain.zig` / `enclave.zig` (key storage), `cf.zig` (CoreFoundation + Security FFI) |
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

## Key providers

The data key that encrypts the vault is acquired one of four ways (`hushd <flag>`):

| flag | key storage | Touch ID | signed build? |
|-|-|-|-|
| `--keychain` *(default)* | login Keychain, device-bound | no | no |
| `--touch-id` | Keychain item with a `UserPresence` access control | every unlock | **yes** |
| `--secure-enclave` | data key wrapped by a Secure Enclave key | every unlock | **yes** |
| `--ephemeral` | random key in memory (survives nothing) | — | no |

The two Touch ID providers use the macOS *data-protection keychain* / Secure
Enclave, which reject access from binaries without a keychain entitlement bound to
a valid Apple Developer Team ID — an unsigned or ad-hoc build gets
`errSecMissingEntitlement` (-34018). To enable them:

```sh
# 1. put your Team ID in hush.entitlements (replace TEAMID)
# 2. sign the binary
scripts/sign.sh "Apple Development: you@example.com (XXXXXXXXXX)"
# 3. run
hushd --touch-id
```

The default `--keychain` provider needs none of this and is what's verified in CI.

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

- **Touch ID requires a code-signed build.** Both biometric providers are implemented
  but the data-protection keychain / Secure Enclave reject unsigned binaries (see
  [Key providers](#key-providers)). The default `--keychain` provider is the one
  verified end-to-end here.
- **Rebuilding `hushd` may prompt once.** The Keychain ACL is bound to the binary's
  code identity, so a fresh build can trigger a one-time "hushd wants to use a key"
  prompt on the next key read — click *Always Allow*. A signed release build has a
  stable identity.
- Per-environment caching policy (cache low-sensitivity envs, always-prompt for prod)
  is not implemented; the chosen provider applies to the whole vault.
- Single client served at a time (sequential accept).
- No `hush run` wrapper, manifest, audit log or menubar UI yet.

## Roadmap

1. ✅ Daemon + CLI + socket + `mlock` store + encrypted file
2. ✅ Keychain-backed data key (reboot-safe); Touch ID providers implemented
   (`--touch-id`, `--secure-enclave`) — pending a code-signed build to validate
3. Audit log + rotation
4. `.vault.toml` manifest (least-privilege, replaces `.env.example`)
5. `hush run --env=<e> -- <cmd>` wrapper (inject at `execve`)
6. Provider federation (1Password / Keeper references)
7. Menubar UI
