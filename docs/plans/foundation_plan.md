# Foundation Setup Plan — PhishDetect

**Status:** Phase 1 (pre-build hardening) · Owner: maintainer · Created 2026-06-26

A robust, correct foundation before any more features land. Grounded in what's actually in the
repo today and what aligns with the **PhishSkill MVP** (`~/Desktop/mvp/`) at the *integration
seams* — not by cloning the MVP's frontend stack.

> Context: the intern landed a lot of working code quickly, but the foundation has **parallel
> realities that drift** (dev=SQLite / prod=Postgres, Redis in infra but absent from code, three
> divergent `requirements*.txt`). This plan collapses those into one reality.

---

## Guiding principles

- **Python stays.** This is an AI/ML detection tool — Python is the right, non-negotiable choice.
- **Isolated, integration-ready.** Align with the MVP only at the *seams*: PostgreSQL 16, Redis 7,
  and the API contract / data shapes already documented in
  [`.claude/context/mvp-alignment.md`](.claude/context/mvp-alignment.md). **Not** by version-matching
  the React stack.
- **One command up.** `docker compose up` at the repo root brings the whole stack online, healthy,
  in the right order — no juggling multiple terminals.
- **One reality.** Eliminate every place where dev behaves differently from what ships.
- **React stays as-is.** React 18 / Vite 5 / current `package.json`. Build it correctly; do **not**
  bump versions in this pass.
- **One source of truth (DRY).** If a function/logic is used more than once, it lives in **one
  module** and everyone imports it — change it once, fixed everywhere. No copy-paste logic.
- **Fat Service / Thin Controller.** Business logic lives in `app/services/`; API routes only parse
  the request → call the service → shape the response. (See `.claude/context/principles.md`.)

---

## Current state (machine + repo)

| Piece | Status |
|---|---|
| PostgreSQL 16 | client installed (psql 16.14); server not running locally — will run in Docker |
| Redis | not installed on host — will run in Docker |
| Node 20.19 / npm 11 | ready; matches MVP's `node:20` |
| Python 3.12 (host) | service Dockerfile pins 3.11 — minor skew, dev-only, fine |
| Docker 28 + Compose v2 | available |

**Known foundational cracks to fix (ranked):**
1. Dev runs **SQLite**, prod runs **Postgres** — the Alembic migration is never exercised in dev
   (`services/app/database.py` auto-switches on the URL; committed `phishdetect.db*` files).
2. **Redis + RQ declared but unused** — no worker, no enqueue; detection runs synchronously in
   `services/app/api/ingest.py`.
3. **Three divergent dependency manifests** — `requirements.txt` / `-dev` / `-local` pin different
   versions (FastAPI 0.115 vs 0.111, **scikit-learn 1.6.1 vs 1.5.1** — the sklearn skew can break
   pickled models).
4. SQLite `.db` artifacts committed; `.gitignore` doesn't exclude them.
5. Migrations run inside the API container `CMD` (races on scale-out); frontend ships **MUI + Tailwind**
   both; `env_file` / `.env.example` paths inconsistent.

---

## Target end state

```
main/
├── docker-compose.yml          # NEW — single source of truth, 4 services
├── docker-compose.override.yml # NEW — dev profile (hot-reload), MVP pattern
├── .env.example  →  .env       # NEW — root, for compose interpolation
├── services/                   # Python API — Postgres-only
│   ├── Dockerfile              # migrations split out of CMD
│   ├── Dockerfile.dev          # NEW — uvicorn --reload
│   └── requirements.txt        # single manifest (+ requirements-dev.txt that *extends* it)
├── frontend/                   # React, unchanged versions, served via nginx in prod
│   ├── Dockerfile
│   └── Dockerfile.dev          # NEW — vite dev server
└── infra/                      # OLD compose removed; keep postgres/init.sql + samples
```

`docker compose up` → Postgres + Redis + API (migrated, on Postgres) + frontend, all healthy.

---

## Phase 1 — Backend onto Postgres (the keystone)

**Why first:** everything downstream sits on the schema. Today the app silently runs SQLite in
dev and Postgres only in Docker, so the migration is never exercised where you develop.

1. Remove the SQLite shim in `services/app/database.py`: delete the `_make_json_column` /
   `_make_uuid_column` dialect branching, the `IS_SQLITE` path, and the `create_all()` fallback.
   Models use `JSONB` / `UUID` directly. *(Already applied as a reference — verify, don't re-add SQLite.)*
2. Alembic becomes the only schema source. `init_db()` stops creating tables; schema comes solely
   from `services/alembic/versions/0001_initial_schema.py`. Verify it matches the current models.
3. Delete committed dev artifacts — `phishdetect.db`, `-shm`, `-wal`; add them to `.gitignore`.
4. Config default in `services/app/config.py` stays Postgres; compose injects the real `DATABASE_URL`.
5. Tests run on Postgres — point `services/tests/conftest.py` at a throwaway test DB/schema so the
   suite exercises real DDL.

**Bring up Postgres & get the `DATABASE_URL` (do this first — it's how you set up the DB):**
```bash
# from main/
cp infra/.env.example .env                 # root env Compose reads (POSTGRES_USER/PASSWORD/DB)
docker compose up -d postgres              # start ONLY postgres first, in isolation
docker compose ps                          # STATUS should be healthy
docker compose exec postgres psql -U phishdetect -d phishdetect -c '\conninfo'   # prove it connects
```
The `DATABASE_URL` has **two forms** — only the host differs:

| Used by | URL |
|---|---|
| Containers (api, migrate) — inside the compose network | `postgresql://phishdetect:phishdetect@postgres:5432/phishdetect` |
| Your laptop (psql, host-run migrations) | `postgresql://phishdetect:phishdetect@localhost:5432/phishdetect` |

Then apply the schema and confirm the tables landed:
```bash
alembic upgrade head
docker compose exec postgres psql -U phishdetect -d phishdetect -c '\dt phishdetect.*'
```

**Acceptance:** `alembic upgrade head` on a clean Postgres builds all 7 tables under `phishdetect.*`;
tests pass against Postgres; `grep -ri sqlite services/` is clean.

## Phase 2 — One Python dependency manifest

**Why:** the three manifests pin different versions; the scikit-learn skew can break pickled models.

1. `requirements.txt` = single runtime source of truth (the full/Docker set).
2. `requirements-dev.txt` = `-r requirements.txt` + test-only tools (pytest, coverage). Never
   re-pins runtime packages.
3. Delete `requirements-local.txt` — its reason to exist disappears once everything runs in Docker.
4. Pin one Python minor (3.11, matching the Dockerfile); note local-3.12 is dev-only.

**Acceptance:** one runtime manifest; dev extends it; no divergent pins; image builds clean.

## Phase 3 — Frontend build correctness (no version bump)

**Why:** keep React 18 / Vite 5 as set up, but make the build production-correct.

1. Resolve dual styling — `frontend/package.json` ships MUI **and** Tailwind. Decide one as primary
   (or keep both only if components genuinely mix them). Confirm before removing anything.
2. Production serve via `nginx:alpine` (MVP serving model) with an SPA-fallback `nginx.conf`,
   replacing `serve`.
3. Vite env — `VITE_API_BASE_URL` is build-time; pass it as a build `ARG`, not runtime env (current
   `infra/docker-compose.yml` sets it at runtime, which Vite ignores).
4. Keep the dev proxy in `frontend/vite.config.ts` for the dev profile.

**Acceptance:** `npm run build` produces a clean `dist`; nginx serves it; SPA routes resolve; app
reaches the API.

## Phase 4 — Unified root docker-compose

**Why:** one command, one source of truth. Promote and correct `infra/docker-compose.yml` to root;
remove the old one.

1. Root `docker-compose.yml` — 4 services on a named bridge network:
   - `postgres:16` + `redis:7.0-alpine` (MVP's exact tags), volumes, healthchecks.
   - `api` — builds `services/Dockerfile`, `depends_on` Postgres healthy, env from root `.env`.
   - `frontend` — builds `frontend/Dockerfile`, nginx, `depends_on` api healthy.
2. Migrations as their own step, out of the API `CMD` — a one-shot `migrate` service
   (`alembic upgrade head`, runs to completion, api waits on it). Matches MVP's "don't migrate in CMD".
3. Root `.env.example` for compose interpolation (`POSTGRES_USER/PASSWORD/DB`); `cp .env.example .env`
   to start. App secrets stay separate.
4. Dev override (`docker-compose.override.yml`, MVP pattern): builds `*.Dockerfile.dev`, volume-mounts
   `src/`, runs uvicorn `--reload` and the Vite dev server.
5. Redis stays in the stack for parity but is **labelled known-unused** (no RQ wiring this phase).

**Acceptance:** from a clean checkout, `cp .env.example .env && docker compose up` → all 4 healthy;
`GET /health` 200; frontend loads and talks to API; `docker compose down -v && up` reproduces it.

## Phase 5 — Verify & document

1. End-to-end smoke: ingest `infra/samples/medium_risk_email.json` → it scores → appears in the
   queue → detail view renders.
2. Update `.claude/context/infra.md` and the root `CLAUDE.md` layout to reflect the real
   (no-longer-greenfield) structure.
3. One-paragraph "running locally" in the README: the single `docker compose up` flow.

---

## Resolved decisions (2026-06-26)

- **Migration tool:** ✅ **Alembic** (Python-native). Schema is defined **once** in the SQLAlchemy
  models; Alembic generates/applies migrations from it. No Prisma, no Node toolchain in the Python
  image, no second schema definition. (Prisma was considered and rejected: it would either duplicate
  the schema or force the less-mature `prisma-client-py` into a Python service.)
- **Database isolation:** ✅ PhishDetect has its **own separate PostgreSQL database**. It aligns with
  the MVP at the **schema/contract level** (Postgres 16, matching table/column shapes,
  `tenant_id` + verdict enums) — *not* by sharing MVP's physical DB.
- **Redis:** ✅ keep in the stack for MVP parity — runs as a service, but RQ wiring (worker +
  enqueue) is deferred to a later phase. Labelled known-unused for now.
- **Frontend styling:** ✅ keep **MUI + Tailwind both**; no version bump (React 18 / Vite 5 stay).
- **Migration step:** ✅ one-shot `migrate` service (`alembic upgrade head`, runs to completion;
  `api` waits on it). Stack launched with `docker compose up --build -d`.
- **Build ownership:** ✅ the engineer (intern) does the implementation; **this single doc is the
  guide** — work top to bottom, one phase at a time, passing each **Acceptance** check before moving on.

---

## Execution order

Phase 1 → 2 → 3 → 4 → 5. Start with **Phase 1** (Postgres keystone) — everything else stacks on it.
