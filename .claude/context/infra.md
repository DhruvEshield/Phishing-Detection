# Infra — Docker, Data, Deployment (`infra/` + project root)

> Load this when working on Docker Compose, environment config, Postgres, Redis, or migrations.

## Current stack (as of 2026-06-27)

All infrastructure runs in Docker. One command brings the full stack up:

```bash
cp .env.example .env
docker compose up --build -d
```

## Service map

| Service | Image | Port | Notes |
|---|---|---|---|
| postgres | postgres:16-alpine | 5432 | Primary data store |
| redis | redis:7.0-alpine | 6379 | Reserved — RQ wiring deferred |
| migrate | services/Dockerfile | — | One-shot: runs `alembic upgrade head`, exits |
| api | services/Dockerfile | 8000 | Waits for migrate to complete |
| frontend | frontend/Dockerfile | 3000→80 | nginx:alpine, SPA fallback |

## Key files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Root — 4 services, production settings |
| `docker-compose.override.yml` | Dev — hot-reload via Dockerfile.dev variants |
| `.env.example` → `.env` | Root env for compose interpolation |
| `infra/postgres/init.sql` | Creates `phishdetect` schema namespace only |
| `infra/samples/` | Sample email fixtures for smoke testing |

## Startup order

Postgres healthy → migrate completes → API starts → frontend starts.
The `migrate` service is intentionally separate from the API — running migrations inside the API CMD is unsafe at scale (race condition on multi-replica deploys).

## Dev vs production

- **Dev:** `docker compose up` — automatically merges `docker-compose.override.yml`, uses `Dockerfile.dev` with hot-reload and source volume mounts
- **Production:** `docker compose -f docker-compose.yml up` — uses production Dockerfiles, nginx serves frontend

## Database

- PostgreSQL 16, schema: `phishdetect`
- Alembic is the only table creator — `init.sql` creates the schema namespace only
- 7 tables: `emails`, `analysis_results`, `queue_entries`, `verdicts`, `blocklist_entries`, `feedback_events`, `audit_logs`
- Redis is running but RQ wiring (worker + enqueue) is deferred — detection runs synchronously for now

## Conventions

- Never run migrations inside the API CMD
- All secrets via `.env` (gitignored) — never in source
- `VITE_API_BASE_URL` is a Docker build ARG, not a runtime env var
