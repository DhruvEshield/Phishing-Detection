# Backend — Detection & ML Services (`services/`)

> Load this when working in `services/` — the Python detection pipeline, API, email
> parsing, scoring engine, and tiered routing.
>
> **Skills:** `backend-patterns`, `api-design` (endpoint shape), `database-migrations`
> (schema changes), `security-review` (auth / input / secrets / new endpoints),
> `tdd-workflow` (write tests first).

## Responsibility

Owns Layer 1's pipeline end-to-end: ingest email → run signal detectors → aggregate into a
**risk score** → route (quarantine / review / deliver) → persist verdict and audit trail.
Also exposes the data the frontend dashboard and Layer 2 monitoring consume.

See [architecture.md](architecture.md) for the signal table and routing tiers.

## Stack (intended direction — pin versions in `requirements.txt` as code lands)

- **API:** FastAPI (async, typed, OpenAPI out of the box) + Uvicorn.
- **Email parsing:** stdlib `email` / `mailparser`; auth checks via DNS + SPF/DKIM/DMARC libs.
- **Task queue / async pipeline:** Celery (or similar) for sandboxing, link-following,
  retro reviews — anything slow or external goes off the request path.
- **Persistence:** PostgreSQL (see [infra.md](infra.md)) for emails, scores, verdicts, audit.

ML inference (content classifier, anomaly, graph, QR) is owned by [ml.md](ml.md); the backend
**calls** those models and turns their outputs into weighted signals — it does not train them.

## Conventions

- **Signals aggregate; they don't individually decide.** Each detector returns a weighted
  contribution to the risk score. No hard-coded single-signal block. Keep weights configurable
  and auditable. (See [principles.md](principles.md) #1.)
- **Explainability from day one.** Every score must be traceable to the signals that produced
  it — store the breakdown, not just the total. Phase 2 formalises this; design for it now.
- **Capture data early.** Log email metadata, verdicts, and analyst decisions from the start
  (within governance limits) — Phase 3 baselines depend on history that only exists if Phase 1
  stored it.
- **Security-first.** This handles email content and account metadata — treat all of it as
  sensitive: least-privilege, encryption, audit trails, retention controls. Run the
  `security-review` skill when touching auth, input handling, secrets, or new endpoints.
- **Rules before ML.** Only reach for a model where [ml.md](ml.md) justifies it; prefer
  heuristics where they suffice.

## API design

Follow the `api-design` skill for resource naming, status codes, pagination, error shape.
The frontend ([frontend.md](frontend.md)) is the primary consumer — surface flagged emails,
risk scores, the signal breakdown (explanation), and verdicts.
