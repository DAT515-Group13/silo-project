# Silo

Silo is a multi-user file storage service built for the DAT515 Cloud Computing course. It has
accounts, teams, per-role quotas, sharing, public links and an admin panel.

- **App:** Python 3.12, FastAPI, async SQLAlchemy, Alembic
- **Database:** PostgreSQL 17
- **Files:** Azure Blob Storage (downloads use short-lived SAS URLs)
- **Deployment:** Kubernetes with Helm, GitHub Actions, Prometheus, Grafana and Loki

## Repository layout

| Path | Contents |
| --- | --- |
| `app/` | The application (routers, services, storage, templates) |
| `migrations/` | Alembic database migrations |
| `tests/` | Pytest suite (`db` marks tests that need PostgreSQL) |
| `helm/` | Charts for the app (`silo`) and the database (`silo-postgres`) |
| `k8s/cluster/` | One-time cluster setup (namespaces, Traefik, monitoring, CI access) |
| `scripts/` | Secrets, Azure setup, smoke test, backup and restore tests |
| `monitoring/` | Grafana dashboard |
| `docs/evidence/` | Command output from the clusters (HPA, probes, backups, network policies) |

## Run locally

You need Docker and an Azure storage account. There is no blob storage emulator.

```sh
cp .env.dev.example .env.dev   # replace every value marked CHANGE
docker compose up --build
```

Compose starts PostgreSQL, runs the migrations once, and then starts the app on
<http://127.0.0.1:8000>. Metrics are served on port 9000. `.env.dev` is ignored by git. Never
commit it.

## Health checks

`/healthz` answers 200 while the process runs. `/readyz` also checks PostgreSQL and the blob
container and answers 503 if either fails. Kubernetes uses them as liveness and readiness probes.

## Tests and lint

```sh
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/pytest -m 'not db'
```

The `db` tests need a PostgreSQL database named `silo_test`, set in `TEST_DATABASE_URL`. They
drop its schema, so never point them at real data. `scripts/run-db-tests.sh <namespace>` runs
them against a cluster database through a port-forward.

## Deploy

CI (`.github/workflows/project-ci.yml`) tests, scans and builds the image on every pull request
and deploys it to `dev`. A push to `main` deploys to `prod`, which needs a manual approval.

Deploy by hand with the Makefile (`ENV` is `dev` or `prod`):

```sh
make cluster            # one-time cluster setup
make secrets ENV=dev    # create the Kubernetes secrets
make db ENV=dev         # PostgreSQL release
make deploy ENV=dev     # app release (TAG defaults to the current commit)
make verify ENV=dev     # smoke test
```

See `helm/README.md` for rollback and release history.

