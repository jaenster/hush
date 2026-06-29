# Recipes

How to wire hush into the tools you already use. The pattern is always the same:

```sh
hush -- <command>
```

runs the command with the env's secrets injected into its environment — nothing is
written to disk, and the secrets vanish when the command exits. The env defaults to
`$HUSH_ENV`, then `dev`, so most of the time it really is just `hush -- <cmd>`.

## Node — package.json

Prefix your scripts. No `dotenv` dependency, no `.env` file.

```json
{
  "scripts": {
    "dev":     "hush -- vite",
    "start":   "hush --env=prod -- node server.js",
    "migrate": "hush -- prisma migrate deploy",
    "test":    "hush --env=test -- vitest"
  }
}
```

`npm run dev` now sees `DATABASE_URL`, `STRIPE_KEY`, … from your `dev` env. You can
delete `import 'dotenv/config'` — the variables are already in `process.env`.

The same works for any package manager and framework, since they all just run a
command:

```jsonc
"dev": "hush -- next dev"      // Next.js
"dev": "hush -- pnpm dev"      // wrap the whole tool
"start": "hush -- bun run index.ts"
```

For Vite/Next client-exposed variables, set them with the framework's prefix:

```sh
hush set dev VITE_API_URL https://api.example.com
hush set dev NEXT_PUBLIC_ANALYTICS_ID abc123
```

## Docker

```sh
# pass the whole env in
docker run --env-file <(hush env --format=dotenv) myimage

# or a single build secret, never written to disk
docker build --secret id=db,src=<(hush get prod DATABASE_URL) .
```

## docker-compose

```yaml
# generate the file first:  hush env --env=prod --format=dotenv > .env.prod
services:
  app:
    env_file: .env.prod
```

Or inject at launch and skip the file entirely:

```sh
hush -- docker compose up
```

## Makefile

```make
run:
	hush -- node server.js

deploy:
	hush --env=prod -- ./deploy.sh

db-migrate:
	hush -- prisma migrate deploy
```

## Justfile

```just
dev:
    hush -- cargo run

migrate:
    hush -- sqlx migrate run
```

## Procfile — foreman / overmind / honcho

```procfile
web:    hush -- node server.js
worker: hush -- node worker.js
```

## Python — uv / poetry / Django

```sh
hush -- python manage.py runserver
hush -- uv run pytest
hush --env=prod -- gunicorn app:wsgi
hush -- poetry run flask run
```

## Go, Rust, anything

hush is language-agnostic — it only sets environment variables:

```sh
hush -- go run .
hush -- cargo run
hush -- ./my-binary
```

## Your interactive shell

Load an env into the current shell, the way `ssh-agent` or `brew shellenv` do:

```sh
eval "$(hush env)"               # dev
eval "$(hush env --env=prod)"
```

Prefer `hush -- <cmd>` for one-offs — with `eval` the secrets persist in your shell
and leak into everything it spawns. See [Getting started](getting-started.md#load-secrets-into-your-shell)
for the trade-off.

## CI / production

hush is a *local development* tool. In CI and on servers, use that platform's secret
store (GitHub Actions secrets, your orchestrator's env, a cloud secrets manager). To
keep the exact same `KEY=value` contract, `hush env --format=dotenv` emits a file any
of them can consume — or point hush at the same backend with a
[provider reference](providers.md) so dev and prod resolve identically.

## Share an env with your team

Commit a [`hush.yaml` manifest](manifest.md): non-secret config inline, secrets as
references or `required` slots. Teammates run `hush -- <cmd>` from the repo and get
the same contract — the `.env.example` that actually injects.
