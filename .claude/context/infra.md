# Infra — Docker, Data, Deployment, Monitoring (`infra/`)

> Load this when working in `infra/` — containerisation, the data store, task-queue infra,
> deployment, and observability.
>
> **Skills:** `docker-patterns` (compose, container security, networking, volumes),
> `deployment-patterns` (CI/CD, health checks, rollback, prod readiness),
> `database-migrations` (PostgreSQL schema changes).

## What lives here

- **Containerisation:** Docker for all services; health checks, metrics, and structured
  logging are **required**, not optional — this is a production-grade MVP target.
- **Relational store:** PostgreSQL — emails, scores, verdicts, audit trail. The audit trail is
  load-bearing for explainability and the feedback loop ([architecture.md](architecture.md)).
- **Task-queue infra:** backing for Celery (or similar) — sandboxing, link-following,
  retroactive reviews. (Owned operationally here; used by [backend.md](backend.md).)
- **Threat-intel feed integrations** + internal blocklist storage.
- **Sandbox infrastructure (Phase 2):** scoped, cost-aware — **not** every attachment is
  detonated. When scope vs. cost is in tension, favour the scoped option and flag the trade-off.

## Conventions

- **Security & privacy first.** Email content + account metadata are sensitive: least-privilege
  access, encryption at rest/in transit, retention controls. (See [principles.md](principles.md) #7.)
- **Measurable at each stage.** Expose detection rate, false-positive rate, and analyst load as
  metrics — every phase must prove value standalone. (See [principles.md](principles.md) #8.)
- **Cost-aware by default** for sandboxing and ML inference infra — flag the trade-off rather
  than silently scaling up.

When introducing a new dependency or service, record the rationale in the main
[CLAUDE.md](../../CLAUDE.md) so the next assistant inherits the decision.
