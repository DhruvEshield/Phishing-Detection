# Phase 1 — Production-Grade Phishing Detection MVP

**Version:** v0.1.0 · Phase 1 plan · last updated 2026-06-25

## What This Builds

A fully runnable `docker compose up` stack for pre-delivery email phishing detection. The system ingests parsed emails, runs five signal detectors in parallel, aggregates them into a single weighted risk score with a structured explanation object, and routes the result to quarantine, analyst review queue, or delivery. Medium-risk emails appear in a React (Vite) analyst dashboard where an analyst can approve or quarantine — feeding back into the system.

> **Phase gate respected:** No Phase 3 behavioural analytics, relationship graphs, OAuth monitoring, or per-user baselines are included. The feedback loop *interface* is wired even though Layer 2 doesn't exist yet.

---

## Open Questions

> [!NOTE]
> **Decisions updated 2026-06-25.** Q1 and Q2 are resolved; the frontend stack was chosen to stay
> consistent with **PhishSkill** (the platform this tool connects to later). The conventions that
> keep it integration-ready live in one lean file:
> [.claude/context/phishskill-integration.md](.claude/context/phishskill-integration.md).

> [!IMPORTANT]
> **Q1 — Phishing corpus → RESOLVED.** The public **phishing_pot** corpus (8,614 real phishing
> `.eml`) is vendored into this repo at `ml/data/phishing_pot/` (raw emails gitignored;
> provenance in `ml/data/README.md`). This replaces the assumed TREC/Ling-Spam phishing source —
> it's real, modern, with intact headers/URLs (also doubles as detector fixtures). **Still
> needed:** a legitimate (ham) class for the binary classifier — pair phishing_pot with
> **Enron-ham** (or a sanitised internal sample). Classifier stays a TF-IDF + LogisticRegression
> baseline behind the `ContentClassifier` interface.

> [!IMPORTANT]
> **Q2 — Domain-age / DNS provider → RESOLVED (upgraded).** Build our **own** domain intelligence
> in Python (standalone — no external dependency): **RDAP** (not raw `python-whois`) for domain
> age, one self-protecting parser per signal, mandatory SSRF guard, DKIM selector-probing, and a
> single structured DNS-analysis output object. Details:
> [phishskill-integration.md](.claude/context/phishskill-integration.md) §1. This subsumes most of
> the `HeaderAnalyzer` SPF/DKIM/DMARC work in §2.

> [!IMPORTANT]
> **Q4 — Frontend stack → CHANGED to stay consistent with PhishSkill.** Build the analyst
> dashboard with **Vite + React + React Router** (Tailwind + MUI), **not Next.js**. The dashboard
> is an auth-gated SPA (no SSR/SEO need), and matching PhishSkill's stack means the two dashboards
> feel like one product once connected. Details:
> [phishskill-integration.md](.claude/context/phishskill-integration.md) §3. (Supersedes the
> "Next.js 14" references in §4 below.)

> [!NOTE]
> **Q3 — QR dependency:** `pyzbar` requires `libzbar` system library. On Linux (Docker), this installs via `apt-get install -y libzbar0`. The Dockerfile will handle it. On Windows dev outside Docker, you need `zbar` separately — documented in the README.

---

## Build Order and Rationale

```
1. infra/           — Docker Compose + Postgres + Redis + Alembic migrations
2. services/        — FastAPI pipeline: ingest → detectors → scoring → routing
3. ml/              — content classifier training + inference wrapper
4. frontend/        — React (Vite) analyst queue + detail + action views
```

**Why this order:** Infra first so every subsequent component has a working DB and queue to target. Services second because the scoring engine's invariants must be tested before anything consumes them. ML third because the content module in services stubs the classifier interface, and the real model can be dropped in after. Frontend last — it's a consumer of an already-defined API shape.

---

## Proposed Changes

### 1. Infrastructure (`infra/`)

#### [NEW] `infra/docker-compose.yml`
Four services: `postgres`, `redis`, `api` (FastAPI/Uvicorn), `frontend` (Vite/React). Healthchecks on all. Environment variables via `.env.example` — no secrets in source.

#### [NEW] `infra/postgres/init.sql`
Empty placeholder — Alembic owns the schema.

#### [NEW] `infra/.env.example`
All required env vars documented with safe defaults.

#### [NEW] `infra/nginx/` (optional, Phase 1 minimal)
Not included — frontend proxies to the API directly via Docker network on port 8000.

---

### 2. Backend Services (`services/`)

#### [NEW] `services/Dockerfile`
Python 3.11-slim + `libzbar0` (for pyzbar), requirements installed, non-root user.

#### [NEW] `services/requirements.txt`
Pinned versions: `fastapi`, `uvicorn[standard]`, `sqlalchemy`, `alembic`, `psycopg2-binary`, `redis`, `rq`, `pydantic`, `python-whois`, `dnspython`, `pyspf`, `dkimpy`, `tldextract`, `requests`, `pyzbar`, `Pillow`, `opencv-python-headless`, `scikit-learn`, `joblib`, `python-multipart`, `structlog`.

#### [NEW] `services/app/main.py`
FastAPI app with CORS, lifespan DB init, structured logging.

#### [NEW] `services/app/api/ingest.py`
`POST /api/v1/emails/ingest` — accepts `EmailIngestRequest` (headers dict, body text, attachments metadata, raw MIME optional). Returns `EmailAnalysisResponse` (email_id, risk_score 0–100, risk_tier, explanation object, routing_decision). No silent quarantine without explanation — enforced by making `explanation` a required field on the response model.

#### [NEW] `services/app/api/queue.py`
`GET /api/v1/queue` — paginated list of medium-risk emails awaiting analyst review.
`GET /api/v1/queue/{email_id}` — full detail with explanation breakdown.

#### [NEW] `services/app/api/verdicts.py`
`POST /api/v1/verdicts` — analyst action (approve / quarantine) persisted to DB, publishes a `FeedbackEvent` to the internal event bus (stub producer — the consumer doesn't exist yet but the contract is defined).

#### [NEW] `services/app/api/feedback.py`
Defines `FeedbackEvent` dataclass and `FeedbackProducer` interface (stub implementation writes to a `feedback_events` Postgres table — clean swap surface for a real event bus later).

#### [NEW] `services/app/detectors/header.py`
`HeaderAnalyzer` — SPF/DKIM/DMARC via `dnspython`/`pyspf`/`dkimpy`, reply-to mismatch, sender routing anomaly, lookalike display-name (Levenshtein vs known-good list). Returns `HeaderSignal(score: float, weight: float, flags: list[str])`.

#### [NEW] `services/app/detectors/content.py`
`ContentAnalyzer` — takes email body text, calls `ContentClassifier` interface. Returns `ContentSignal`. The interface is the boundary: the real model lives in `ml/`.

#### [NEW] `services/app/detectors/url.py`
`URLAnalyzer` — domain age via `WhoisProvider` interface, redirect-chain following (max 5 hops, timeout-gated), lookalike-domain detection (Levenshtein vs vendor allowlist in config), credential-harvest page heuristics (login form + no HTTPS = flag). Sandbox detonation **stubbed** via `SandboxProvider` interface (raises `NotImplementedError` with a clear message). Returns `URLSignal`.

#### [NEW] `services/app/detectors/qrcode.py`
`QRCodeDetector` — extracts images from email body/attachments (Pillow + OpenCV), decodes QR codes via `pyzbar`, feeds decoded URLs back through `URLAnalyzer`. Returns `QRSignal`.

#### [NEW] `services/app/detectors/threat_intel.py`
`ThreatIntelModule` — `ThreatIntelProvider` interface with `LocalBlocklistAdapter` (queries `blocklist_entries` Postgres table). External feed adapter is a stub. Returns `ThreatIntelSignal`.

#### [NEW] `services/app/scoring/engine.py`
`ScoringEngine` — aggregates all signals into a 0–100 weighted score. **Invariant enforced in code:** each signal's max contribution is capped at `< HIGH_THRESHOLD / signal_count` so no single signal can independently breach the high-risk threshold. Produces `ScoreExplanation(total: float, tier: str, signals: list[SignalBreakdown])`. Config-driven thresholds from env/YAML.

#### [NEW] `services/app/scoring/config.py`
`ScoringConfig` — loads `HIGH_THRESHOLD`, `MEDIUM_THRESHOLD`, `signal_weights` from environment / YAML. Validates that no single weight × max_signal_score ≥ HIGH_THRESHOLD (runtime assertion + unit-testable).

#### [NEW] `services/app/models/` (SQLAlchemy ORM)
- `Email` — id, raw_headers_json, body_text, received_at, routing_decision
- `AnalysisResult` — email_id (FK), risk_score, risk_tier, explanation_json, model_version, created_at
- `QueueEntry` — email_id (FK), status (pending/reviewed), assigned_at
- `Verdict` — email_id (FK), action (approve/quarantine), analyst_id, reason, created_at
- `BlocklistEntry` — domain/ip/hash, source, added_at, expires_at
- `FeedbackEvent` — id, verdict_id (FK), event_type, payload_json, created_at, consumed_at (null = pending)

#### [NEW] `services/alembic/` — Alembic migrations for all above tables

#### [NEW] `services/tests/`
- `test_scoring_invariant.py` — **critical**: parametrised test that sends each signal at max value alone and asserts `total_score < HIGH_THRESHOLD`. Runs in CI.
- `test_header_analyzer.py` — unit tests with mocked DNS.
- `test_url_analyzer.py` — mocked WHOIS + HTTP.
- `test_content_analyzer.py` — mocked classifier.
- `test_qrcode_detector.py` — fixture QR image.
- `test_threat_intel.py` — mocked DB.
- `test_ingest_endpoint.py` — integration test, full pipeline with all external calls mocked.

---

### 3. ML (`ml/`)

#### [NEW] `ml/data/README.md`
Documents the assumption: training uses the publicly available **Enron-Spam dataset** (6 labelled categories, ~33,000 emails). Link provided. Instructions to download. **Clearly flagged assumption.**

#### [NEW] `ml/train.py`
Training script: loads corpus → TF-IDF vectorisation → Logistic Regression → saves model + vectoriser + metadata JSON (version, dataset, metrics, timestamp) to `ml/models/`. `MLflowLogger` stub (writes to local file for now).

#### [NEW] `ml/inference.py`
`ContentClassifier` interface implementation: loads versioned model, exposes `predict(text: str) -> ClassificationResult(label: str, confidence: float, model_version: str)`. Version injected at startup from env, recorded in every `AnalysisResult`.

#### [NEW] `ml/models/` — gitignored (large binaries), built by `train.py`

#### [NEW] `ml/evaluate.py`
Evaluation script: precision, recall, F1 on a held-out test split. Outputs to `ml/reports/`.

#### [NEW] `ml/governance.md`
Retraining and drift-monitoring plan (the required governance doc per ml.md):
- Trigger: F1 drops > 5% on monthly eval, or analyst override rate > 20% over 30 days.
- Process: download new analyst-labelled data from `feedback_events`, retrain, evaluate, version, deploy (manual approval gate).
- Model versions are tracked in the `AnalysisResult` table — drift is visible from production data.

---

### 4. Frontend (`frontend/`)

#### [NEW] `frontend/` — Vite + React + React Router + TypeScript (Tailwind + MUI)

**Routes (React Router):**
- `/` → redirect to `/queue`
- `/queue` — paginated table of medium-risk emails (score, sender, subject, received_at, status). Auto-refreshes every 30s.
- `/queue/:id` — detail view: email metadata + full explanation breakdown (signal cards with name, sub-score, weight, flags). Approve / Quarantine buttons. Action persisted via `POST /api/v1/verdicts`.
- `/queue/:id/success` — confirmation + back to queue.

**Key components:**
- `SignalBreakdownCard` — renders a single signal's contribution visually (score bar, flags list, weight).
- `RiskBadge` — colour-coded HIGH/MEDIUM/LOW chip.
- `ExplanationPanel` — composes all `SignalBreakdownCard`s.
- `VerdictActions` — Approve/Quarantine with reason textarea, disabled until analyst reads explanation.

**API client:** typed fetch wrapper in `lib/api.ts` using the backend's OpenAPI types.

---

### 5. Context File Updates

#### [MODIFY] `.claude/context/backend.md`
Add: stack decisions (FastAPI + SQLAlchemy + Alembic + RQ), detector interfaces, scoring engine invariant, feedback contract location.

#### [MODIFY] `.claude/context/ml.md`
Add: content classifier stack (TF-IDF + LR baseline, Enron-Spam corpus assumption flagged), inference wrapper shape, governance doc location (`ml/governance.md`).

#### [MODIFY] `.claude/context/infra.md`
Add: Docker Compose service map, env var pattern, Redis for RQ, Postgres for schema.

#### [MODIFY] `.claude/context/frontend.md`
Add: Vite + React + React Router, route map, key components, API client pattern.

---

## Key Invariants Enforced in Code (not just convention)

| Rule | Where enforced |
|---|---|
| No single signal independently blocks | `ScoringEngine` caps per-signal max contribution; `test_scoring_invariant.py` proves it parametrically |
| No quarantine without explanation | `EmailAnalysisResponse.explanation` is a non-optional Pydantic field; API returns 422 if missing |
| Human review path always exists | High-risk emails go to quarantine **but** are still stored with full explanation + verdict endpoint available |
| Phase 3 not built | No behavioural baselines, relationship graphs, or OAuth monitoring — only the pre-delivery pipeline |
| Feedback loop interface in place | `FeedbackEvent` + `FeedbackProducer` interface + `feedback_events` table — Layer 2 consumer can be plugged in later |

---

## Verification Plan

### Automated Tests (CI on every push)
```bash
# Backend
cd services && pytest tests/ -v --cov=app
# Specifically: scoring invariant test
pytest tests/test_scoring_invariant.py -v

# Type check
mypy services/app --strict

# Lint
ruff check services/ ml/

# Frontend
cd frontend && npm run type-check && npm run lint
```

### Integration Test (Docker)
```bash
docker compose up -d
# Wait for health checks
curl -X POST http://localhost:8000/api/v1/emails/ingest \
  -H 'Content-Type: application/json' \
  -d @infra/samples/medium_risk_email.json
# Assert: response has risk_score, explanation, routing_decision
# Assert: GET /api/v1/queue returns the email
# Assert: POST /api/v1/verdicts with action=quarantine returns 200
```

### Manual Verification
1. `docker compose up` → all services healthy
2. POST sample email → receive score + explanation JSON
3. Open `http://localhost:3000/queue` → email appears in queue
4. Click into detail → see signal breakdown cards
5. Click "Quarantine" → action persisted, email removed from pending queue
