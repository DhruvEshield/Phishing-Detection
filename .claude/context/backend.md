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

## Stack (confirmed — Phase 1 built)
- **API:** FastAPI 0.115.5 + Uvicorn 0.32.0. Async, typed, OpenAPI auto-generated.
- **Email auth checks:** dnspython, pyspf, dkimpy for SPF/DKIM/DMARC validation.
- **Task queue:** Redis + RQ declared in stack. RQ wiring (worker + enqueue) deferred — detection runs synchronously for now.
- **Persistence:** PostgreSQL 16 via SQLAlchemy 2.0 + Alembic migrations. 7 tables under `phishdetect` schema.
- **ML inference:** ContentClassifier interface in `ml/inference.py` — backend calls it, never trains.

## Detectors (all built and tested)
| Detector | File | What it checks |
|---|---|---|
| HeaderAnalyzer | `app/detectors/header.py` | SPF/DKIM/DMARC, reply-to mismatch, lookalike display name |
| ContentAnalyzer | `app/detectors/content.py` | Urgency language (rules) + ML classifier (TF-IDF + LR) |
| URLAnalyzer | `app/detectors/url.py` | Credential harvest pages, lookalike domains, redirect chains |
| QRCodeDetector | `app/detectors/qrcode_detector.py` | QR codes in images, decoded URLs fed through URLAnalyzer |
| ThreatIntelModule | `app/detectors/threat_intel.py` | Blocklist lookups against `blocklist_entries` table |

## Scoring engine
`app/scoring/engine.py` — aggregates all 5 signals into a 0–100 weighted score.
**Invariant enforced in code:** no single signal can independently breach `HIGH_THRESHOLD`.
`test_scoring_invariant.py` proves this parametrically for every signal.

## API endpoints
- `POST /api/v1/emails/ingest` — ingest + score + persist + route
- `GET /api/v1/queue` — paginated analyst review queue
- `GET /api/v1/queue/{email_id}` — full detail with signal breakdown
- `POST /api/v1/verdicts` — analyst approve/quarantine, creates FeedbackEvent
- `GET /health` — liveness check

## Feedback loop contract
`FeedbackEvent` + `FeedbackProducer` interface + `feedback_events` table. Stub producer writes to Postgres. Layer 2 consumer plugs in later without changing the interface.

## Tests
38 tests, all passing. Run inside Docker: `docker compose exec api pytest tests/ -v`
Critical: `test_scoring_invariant.py` must always pass — it's a hard CI fail.

## Conventions
- **Signals aggregate; they don't individually decide.** No hard-coded single-signal block.
- **Explainability from day one.** Every score is traceable to signals — stored in `explanation_json`.
- **Rules before ML.** Content analyzer runs rules first, blends ML score on top.
- **Security-first.** Least-privilege, audit trails, retention controls on all email data.
