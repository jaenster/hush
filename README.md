# hush

A macOS-local secrets daemon that replaces `.env` files — think *ssh-agent, but for
environment variables*. Secrets live encrypted on disk and in `mlock`'d memory; a
small CLI talks to a background daemon over a `0600` unix domain socket.

> **Status: early MVP.** The daemon, CLI, wire protocol, encrypted store, memory
> hygiene, Keychain-backed key storage, and 1Password/Keeper federation are
> implemented and working. Secrets survive restarts and reboots. Touch ID gating
> is implemented but needs a code-signed build — see [Key providers](#key-providers).

📖 **Full documentation: [`docs/`](docs/README.md)** — getting started, CLI
reference, providers, security model, wire protocol, architecture.

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
separate. Already have a `.env`? `hush import .env --env=dev` migrates it in one shot.

### Replacing `.env`

`hush run` resolves an env's secrets and injects them into a command — the secrets
never touch disk and the daemon is the only thing that ever held them decrypted:

```sh
hush set dev DATABASE_URL postgres://localhost/app
hush set dev STRIPE_KEY sk_test_123

hush -- node server.js          # implicit env (defaults to dev); injects both secrets
hush --env=prod -- ./deploy.sh  # explicit env
hush -- printenv STRIPE_KEY     # -> sk_test_123
```

The command inherits your normal environment with the env's secrets layered on top,
and `hush` exits with the command's exit code. The env defaults to `$HUSH_ENV`, then
`dev`, so most of the time it's just `hush -- <cmd>`.

To load secrets into your **current** shell instead of a child process (like
`ssh-agent` or `brew shellenv`):

```sh
eval "$(hush env)"              # or: source <(hush env --env=prod)
```

`hush -- <cmd>` is preferred — the secrets live only in the child process and vanish
when it exits. `eval "$(hush env)"` is handy for interactive sessions but the secrets
then persist in your shell and leak into everything it spawns.

### Docker / Compose / CI

`hush env --format=dotenv` prints `KEY=value` lines, which compose with anything that
reads an env file — no Docker-specific integration, hush just stays a secrets source:

```sh
docker run --env-file <(hush env --env=prod --format=dotenv) myimage
docker build --secret id=db,src=<(hush get prod DATABASE_URL) .
```

```yaml
# docker-compose.yml — generate the env file first:
#   hush env --env=prod --format=dotenv > .env.prod
services:
  app:
    env_file: .env.prod
```

`--format` accepts `shell` (default) or `dotenv` (aliases: `docker`, `env-file`).
Multi-line secret values can't be represented in an env file, so they're skipped
with a warning in `dotenv` format.

### Federate to 1Password / Keeper

A value can be a **reference** into an external manager instead of an inline
secret. hush resolves it on read (shelling out to the provider CLI), so the real
secret never touches hush's disk — only the reference is stored:

```sh
hush set prod DATABASE_URL 'op://Private/app-db/url'      # 1Password
hush set prod API_TOKEN    'keeper://abc123/field/token'  # Keeper

hush get prod DATABASE_URL     # runs `op read ...`, prints the real value
hush -- ./server               # injects the resolved values
```

Built-in: `op://` (1Password), `keeper://` (Keeper), `aws://` (Secrets Manager),
`gopass://`, `pass://`, `vault://` (HashiCorp). The provider CLI must be
installed and authenticated in the daemon's environment. Adding another is a
one-line table entry — see [docs/providers.md](docs/providers.md).

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
field             = u32_le len | bytes
```

Keys must be valid env var names (`[A-Za-z_][A-Za-z0-9_]*`); the daemon rejects
anything else at `set`, since keys are injected as environment variables.

`op`: ping=0, set=1, get=2, del=3, list=4, dump=5 (all pairs in an env, for `run`).
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
- Single client served at a time (sequential accept) — a client that connects and
  stalls without sending wedges the daemon for others until it disconnects. Needs
  per-connection concurrency + a thread-safe store to fix.
- No `hush run` wrapper, manifest, audit log or menubar UI yet.

## Roadmap

1. ✅ Daemon + CLI + socket + `mlock` store + encrypted file
2. ✅ Keychain-backed data key (reboot-safe); Touch ID providers implemented
   (`--touch-id`, `--secure-enclave`) — pending a code-signed build to validate
3. ✅ `hush run --env=<e> -- <cmd>` wrapper (inject env, exec the command)
4. ✅ Provider federation — `op://` (1Password) and `keeper://` (Keeper) references
5. Audit log + rotation
6. Project manifest (least-privilege, k8s-flavored, replaces `.env.example`)
7. Per-connection concurrency (fix the sequential-accept wedge)
8. Menubar UI
