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

## Includes: one reference → many vars

A normal reference resolves to *one* value. An **include** resolves to a whole
**set** of vars — the env-manager move that a password manager has no concept
of. The unit you share with a team isn't a secret, it's the set: put the dev
config in one shared 1Password secure note (or a JSON secret, or a whole vault),
point every machine's hush at it, and rotation happens once at the source. The
expanded secrets are **never written to hush's disk** — only the directive is.

```sh
# A shared secure note whose body is a .env file:
hush include dev op://Private/myapp-dev --as=dotenv

# A JSON secret (AWS Secrets Manager, Vault, an op note holding JSON):
hush include prod aws://prod/app-secrets --as=json

# A whole container, every item prefixed (prefix is required, see below):
hush include dev op://Work --as=enumerate --prefix=WORK_

hush includes dev            # list directives
hush exclude  dev op://Work  # remove one
```

Modes — all three differ only in how the provider output becomes pairs:

| `--as=` | provider returns | parsed as |
|-|-|-|
| `dotenv` *(default)* | a text blob of `KEY=value` lines | the `.env` parser |
| `json` | a JSON object | each top-level key → a var (scalars stringified) |
| `enumerate` | a whole container | the provider's `list_argv` recipe, as `KEY=value` lines |

`dotenv` and `json` reuse the provider's normal read recipe, so they work for
**any** provider that returns text or JSON — including AWS/Vault, whose natural
unit is already a multi-field blob. `enumerate` needs a per-provider
whole-container recipe (`list_argv`); it's wired generically but ships without a
built-in recipe, so for now it's used with a custom registry entry.

**Precedence** (config-style): includes layer in the order added (a later
include overrides an earlier one), and an env's own `hush set` keys override all
includes. So a shared note gives the defaults; a local `hush set` is the
override.

**Safety**: a key from a remote source that isn't a valid env var name is
skipped, never injected. `enumerate` (whole container) **requires** `--prefix`,
since dumping a vault flat invites name collisions and junk names. And note the
trust boundary — whoever can edit an included note/vault can set any env var in
your processes, so only include sources you control (don't `--as` an untrusted
note into a prod run).

Includes are nested one level deep only: an included `.env` body is not itself
re-scanned for includes.

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
