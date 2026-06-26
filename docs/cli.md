# CLI reference

`hush` is the client; `hushd` is the daemon. All commands talk to a running
`hushd` over the unix socket.

## `hushd` — the daemon

```
hushd [--keychain | --touch-id | --secure-enclave | --ephemeral]
```

Key provider flags (default `--keychain`) — see [key-providers.md](key-providers.md):

| flag | data key storage | Touch ID | needs signed build |
|-|-|-|-|
| `--keychain` *(default)* | login Keychain, device-bound | no | no |
| `--touch-id` | Keychain item with a UserPresence access control | every unlock | yes |
| `--secure-enclave` | data key wrapped by a Secure Enclave key | every unlock | yes |
| `--ephemeral` | random key in memory (survives nothing) | — | no |

On `SIGINT`/`SIGTERM` the daemon removes its socket and exits.

## `hush` — the client

### `hush -- <command> [args...]`
Resolve the env's secrets, layer them on the current environment, and exec the
command (replacing the `hush` process). Exits with the command's status.

```sh
hush -- node server.js
hush --env=prod -- ./deploy.sh
```

The env is chosen as: `--env=<env>` → `$HUSH_ENV` → `dev`.
`hush run -- <command>` is an explicit alias for the same thing.

### `hush env [--env=<env>] [--format=shell|dotenv]`
Print the env's secrets for evaluation or an env file.

```sh
eval "$(hush env)"                                  # load into current shell
docker run --env-file <(hush env --format=dotenv)   # KEY=value lines
```

- `shell` (default): `export KEY='value'`, shell-quoted. For `eval`/`source`.
- `dotenv` (aliases `docker`, `env-file`): raw `KEY=value`. Multi-line values
  are skipped (env files can't represent them).

### `hush import <file.env> [--env=<env>]`
Bulk-import a `.env` file into an env (one secret per `KEY=value` line).
Understands `export` prefixes, `#` comments, blank lines, and single/double
quotes (double-quoted values expand `\n \r \t`). Keys that aren't valid env var
names are skipped with a warning. Reuses a single connection.

```sh
hush import .env --env=dev      # migrate an existing project in one shot
```

### `hush set <env> <key> <value>`
Store a secret. `<key>` must be a valid env var name (`[A-Za-z_][A-Za-z0-9_]*`).
The value may be a literal or a [provider reference](providers.md)
(`op://…`, `keeper://…`).

### `hush get <env> <key>`
Print one secret's value (resolving a reference if needed). Exit 1 + "not found"
if absent.

### `hush del <env> <key>`
Remove a secret. Exit 1 if it didn't exist.

### `hush ls <env>`
List the key names in an env (values not shown).

### `hush ping`
Check that the daemon is reachable.

### `hush version` / `hush help`

## Exit codes

| code | meaning |
|-|-|
| 0 | success |
| 1 | not found / daemon unreachable / reference resolution failed |
| 2 | usage error (bad arguments) |
| * | for `hush -- <cmd>`, the command's own exit code |

## Environment variables

- `HUSH_ENV` — default env when `--env` is not given.
