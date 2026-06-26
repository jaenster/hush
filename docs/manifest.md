# The project manifest (`hush.yaml`)

A `hush.yaml` checked into the repo is the project's **env contract**: it
declares which variables the code needs, where each comes from, and — for
non-secret config — its value inline. It replaces `.env.example`, except it
actually does something: `hush` reads it automatically and injects accordingly.

hush walks up from the working directory to find it (like git finding `.git`),
so any subdirectory of the project sees the same manifest.

Environments are **independent blocks** under `envs:` — no inheritance, each is
self-contained. `default:` picks the env when neither `--env` nor `$HUSH_ENV` is
given.

```yaml
# hush.yaml — committed, code-reviewed
default: dev
envs:
  dev:
    vars:
      PORT:         3000                     # inline literal — not a secret, lives in git
      DATABASE_URL: op://Private/db-dev      # provider reference — resolved live, never stored
      STRIPE_KEY:   required                 # a real secret — must come from local `hush set`
      WEIRD:        literal://required       # escape hatch — the literal string "required"
    includes:
      - op://Private/team-dev --as=dotenv    # bulk source (see providers.md)
  prod:
    vars:
      PORT:         80
      DATABASE_URL: op://Private/db-prod
      STRIPE_KEY:   required
    includes:
      - op://Private/team-prod --as=dotenv
```

A variable's value is read as one of:

| value | meaning |
|-|-|
| a provider reference (`op://…`, `aws://…`) | resolved live at injection, never stored on disk |
| `literal://X` | the verbatim string `X` — escape hatch (see below) |
| `required` | a slot: the value must come from a local `hush set`; missing ⇒ error |
| `optional` | a slot that may be absent |
| anything else (`3000`, `development`) | an inline literal — for non-secret config |

The split is the point: **secrets** are references or `required` slots and never
touch the committed file; **non-secret config** (ports, log levels, `NODE_ENV`)
lives inline where it's reviewable and travels with the code. A fresh clone plus
a running daemon works for everything except the `required` secrets, which each
developer sets once locally.

`literal://` exists because `required`/`optional` are reserved bare words: a
secret whose value is genuinely the string `required` would otherwise read as a
slot. `literal://required` forces the literal. It also force-quotes a value that
happens to look like a provider reference, and `literal://` alone is an explicit
empty string.

## Precedence

Sources layer so that **explicit beats bulk** and **local beats committed**:

1. manifest `includes:` (committed bulk)
2. vault include directives (local bulk, `hush include`)
3. manifest `vars:` (committed explicit)
4. local `hush set` keys (local explicit)

So a shared include gives defaults, a manifest `vars:` entry pins a project
value, and a local `hush set` is your machine's override on top.

## The allowlist (why this is safe)

An included note or vault is editable by whoever controls it — and an env var
like `PATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` or `NODE_OPTIONS` doesn't just
configure a process, it changes what code that process loads. Left unchecked, a
shared note becomes a way to run code on every machine that includes it.

So a **bulk source may not inject a process-sensitive name** (the
dynamic-linker families plus a curated set — see `names.isDangerous`) **unless
the manifest's `vars:` explicitly declares it.** An ordinary new var from a note
(`FEATURE_X`) flows through — dev picks up extra vars all the time, that's fine.
A dangerous one is dropped with a warning naming it.

Because the allowlist lives in `hush.yaml`, opting a dangerous name in is a
reviewed change: nobody's machine honours `PATH:` from a note until the PR
adding `PATH` to the manifest is merged and pulled. The four-eyes of code review
*is* the security boundary. The hardcoded dangerous-name floor still applies
when there's no manifest, so vault includes are protected either way.

Declared-but-explicit values (a manifest `vars:` entry) and your own local
`hush set` are never filtered — those are you, not a shared source.

## Notes

- The grammar is a small YAML subset: top-level `default:` and `envs:`; under
  `envs:`, each bare `name:` opens an env block (or a `vars:` / `includes:`
  section within it); a `NAME: value` line is a var and a `- <ref> [--as=…]
  [--prefix=…]` line is an include. No anchors or flow style. A trailing
  ` # comment` is stripped (whitespace-preceded, so a `#` inside a value
  survives). Env names can't be `vars` or `includes`.
- env precedence for the run: `--env=` flag, then `$HUSH_ENV`, then the
  manifest's `default:`, then `dev`. An env not present in the manifest just
  contributes nothing (vault-only).
- The manifest is sent to the daemon over the socket and parsed there (it holds
  references and non-secret config only, no secrets), so all resolution stays in
  the daemon where the provider CLIs are authenticated.
