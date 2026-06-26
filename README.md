# hush

A macOS-local secrets daemon that replaces `.env` files — think *ssh-agent, but for
environment variables*. Secrets live encrypted on disk and in `mlock`'d memory; a
small CLI talks to a background daemon over a `0600` unix domain socket.

> **Status: early MVP.** The daemon, CLI, wire protocol, encrypted store and memory
> hygiene are implemented and working. Key management is still a placeholder — see
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
| `daemon/` | `hushd` + `key_provider.zig` (the key-management seam) |
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

- **Encrypted at rest.** The vault is XChaCha20-Poly1305 ciphertext; the data key is
  never written in plaintext by the store. Disk theft yields useless bytes.
- **No swap.** Secret values are held in `mlock`'d memory and zeroed on overwrite,
  delete and shutdown. Request/response buffers carrying secrets are wiped after use.
- **Reboot-safe, not restore-safe** (by design): the design binds the data key to the
  device. Moving to a new machine means re-setup, not recovery.
- **Local-only.** The socket is `0600` and owned by your user; there is no network
  surface.

## Limitations

This is an MVP. Notably:

- **Key management is a placeholder.** `daemon/key_provider.zig` currently returns an
  *ephemeral* random key, so **secrets do not survive a daemon restart**. The daemon
  logs this and tolerates a stale vault by starting empty. The next milestone replaces
  it with a Keychain-stored data key, then a Secure-Enclave-wrapped key gated by
  Touch ID.
- Single client served at a time (sequential accept).
- No `hush run` wrapper, manifest, audit log or menubar UI yet.

## Roadmap

1. ✅ Daemon + CLI + socket + `mlock` store + encrypted file
2. Key management: Keychain → Secure Enclave + Touch ID approval
3. Audit log + rotation
4. `.vault.toml` manifest (least-privilege, replaces `.env.example`)
5. `hush run --env=<e> -- <cmd>` wrapper (inject at `execve`)
6. Provider federation (1Password / Keeper references)
7. Menubar UI
