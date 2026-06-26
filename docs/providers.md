# Provider federation

A vault value can be a **reference** into an external secret manager instead of
an inline secret. hush resolves the reference on read by shelling out to the
provider's CLI, so the real secret is **never written to hush's disk** — only
the reference is stored (encrypted), and the secret is fetched live each time.

This makes hush a *broker* over the vaults you already use rather than yet
another place secrets live.

## Using references

Store a reference exactly like any other value — it's recognized by its URI
scheme:

```sh
hush set prod DATABASE_URL 'op://Private/app-db/url'
hush set prod API_TOKEN    'keeper://abc123/field/token'

hush get prod DATABASE_URL          # runs the provider CLI, prints the real value
hush -- ./server                    # injects resolved values into the process
```

A value whose scheme isn't a known provider (e.g. `postgres://…`) is treated as
a literal and returned unchanged.

## Built-in providers

| scheme | resolved with | invocation |
|-|-|-|
| `op://` | [1Password CLI](https://developer.1password.com/docs/cli/) | `op read --no-newline {ref}` |
| `keeper://` | [Keeper Secrets Manager](https://docs.keeper.io/secrets-manager/) (`ksm`) | `ksm secret notation {ref}` |
| `aws://` | AWS CLI | `aws secretsmanager get-secret-value --secret-id {path} --query SecretString --output text` |
| `gopass://` | [gopass](https://www.gopass.pw/) | `gopass show -o {path}` |
| `pass://` | [pass](https://www.passwordstore.org/) | `pass show {path}` |
| `vault://` | [HashiCorp Vault](https://www.vaultproject.io/) | `vault kv get -field=value {path}` |

`{ref}` is the full reference; `{path}` is the part after `scheme://`. Examples:

```sh
hush set prod DB  'op://Private/app-db/url'        # op read op://Private/app-db/url
hush set prod KEY 'aws://prod/stripe'              # aws ... --secret-id prod/stripe
hush set prod PW  'pass://email/work'              # pass show email/work
```

A single trailing newline from the CLI is trimmed. Note that `pass` prints the
whole entry, so structure the entry's first line as the value (or use `gopass`,
which returns only the secret with `-o`).

## Requirements

The provider CLI must be **installed and authenticated in the daemon's
environment**. `hushd` inherits the environment it was started in, so start it
from a shell where `op` / `ksm` already work:

```sh
op signin            # or have a service-account token in the environment
hushd &
```

If resolution fails (CLI missing, not authenticated, bad reference), `hush get`
exits non-zero with an error and `hushd` logs a warning naming the reference.
Run the provider command yourself to see the detailed error:

```sh
op read op://Private/app-db/url
```

## Notes & trade-offs

- **Latency**: each referenced secret spawns the provider CLI on every read.
  `hush -- cmd` with N references runs the CLI N times. A resolution cache with
  a short TTL is a planned improvement.
- **Auth/biometric**: the provider owns its own unlock (e.g. 1Password's Touch
  ID prompt) — hush does not wrap it, to avoid a double prompt.
- **Mixing**: an env can freely mix literals and references.

## Adding a provider

Providers are a small table in `src/daemon/providers.zig`:

```zig
pub const default_registry = [_]Provider{
    .{ .scheme = "op",     .argv = &.{ "op", "read", "--no-newline", "{ref}" } },
    .{ .scheme = "keeper", .argv = &.{ "ksm", "secret", "notation", "{ref}" } },
};
```

Add an entry with the scheme and the CLI argv template; the tokens `{ref}` (full
reference) and `{path}` (after `scheme://`) are substituted at resolve time.
Anything that prints the secret to stdout works.
