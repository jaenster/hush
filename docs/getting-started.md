# Getting started

## Install

Requires [Zig 0.16](https://ziglang.org/) and [libsodium](https://libsodium.org/)
(`brew install libsodium`). libsodium is linked statically, so the resulting
binaries have no third-party runtime dependency.

```sh
zig build                 # builds hushd + hush into zig-out/bin
zig build test            # runs the unit tests
cp zig-out/bin/hush zig-out/bin/hushd ~/bin   # or wherever you keep tools
```

## Start the daemon

`hushd` is the background daemon that holds your secrets. Start it once:

```sh
hushd &
```

It listens on a `0600` unix socket under `~/Library/Application Support/hush/`,
holds secrets in `mlock`'d memory, and persists them encrypted to `vault.bin`.
By default the data key lives in your login Keychain (survives reboots). See
[key-providers.md](key-providers.md) for the Touch ID options.

## Store and use secrets

Secrets are grouped by *env* (`dev`, `tst`, `prod`, …):

```sh
hush set dev DATABASE_URL postgres://localhost/app
hush set dev STRIPE_KEY   sk_test_123

hush ls dev               # DATABASE_URL, STRIPE_KEY
hush get dev STRIPE_KEY   # sk_test_123
```

Already have a `.env`? Import it in one shot:

```sh
hush import .env --env=dev
```

## Run a command with secrets injected

This is the everyday path — it replaces `.env`:

```sh
hush -- node server.js            # env defaults to $HUSH_ENV, then "dev"
hush --env=prod -- ./deploy.sh
```

The command inherits your normal environment with the env's secrets layered on
top, and `hush` exits with the command's exit code. Secrets live only in the
child process and vanish when it exits.

## Load secrets into your shell

For interactive sessions (less hygienic — secrets persist in the shell):

```sh
eval "$(hush env)"                # or: source <(hush env --env=prod)
```

## Reference secrets in 1Password / Keeper

A value can be a *reference* instead of an inline secret; hush resolves it on
read so the real secret never touches disk. See [providers.md](providers.md):

```sh
hush set prod DATABASE_URL 'op://Private/app-db/url'
hush get prod DATABASE_URL          # runs `op read ...`, prints the real value
```

## Docker / CI

```sh
docker run --env-file <(hush env --env=prod --format=dotenv) myimage
```

## Next

- [CLI reference](cli.md)
- [Concepts & security model](security.md)
- [Provider federation](providers.md)
- [Wire protocol](protocol.md) (for writing SDKs)
- [Architecture](architecture.md)
