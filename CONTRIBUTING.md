# Contributing to hush

Thanks for your interest. `hush` is a macOS-local secrets daemon written in Zig;
contributions of all sizes are welcome.

## Prerequisites

- macOS (the key providers are macOS-specific)
- [Zig 0.16](https://ziglang.org/)
- [libsodium](https://libsodium.org/) — `brew install libsodium`

## Build & test

```sh
zig build            # builds hushd + hush into zig-out/bin
zig build test       # runs the unit tests
```

CI runs exactly these two on macOS with the default `--keychain` provider, so a
green local `zig build test` is a good signal your change will pass.

## Working on it

- **Match the surrounding style.** Read a neighbouring file before adding one.
- **Keep the wire protocol minimal.** It is deliberately tiny so SDKs stay small —
  see [docs/protocol.md](docs/protocol.md). Changes there ripple everywhere.
- **Mind the secret-handling invariants.** Secret bytes live in `mlock`'d memory and
  are zeroed on overwrite/delete/shutdown; request/response buffers carrying secrets
  are wiped after use. Don't introduce a copy that escapes that discipline.
- **Document user-facing changes** in `README.md` and the relevant `docs/` page.

## Pull requests

1. Fork and branch off `main`.
2. Keep the change focused; one concern per PR.
3. Make sure `zig build test` passes.
4. Describe the change and its motivation in the PR body.

## Security issues

Do not file security problems as public issues — see [SECURITY.md](SECURITY.md).
