# PhishDetect — Phase 1 MVP

AI-assisted phishing detection platform. Pre-delivery email analysis with a signal-aggregating risk score and an analyst review queue.

## Quick Start

```bash
# 1. Copy env template
cp infra/.env.example .env

# 2. Train the ML model (optional — runs rules-only if model not present)
#    First, ensure phishing_pot emails are present:
#    cp -r /path/to/phishing_pot/email ml/data/phishing_pot/
python ml/train.py

# 3. Start the full stack
docker compose -f infra/docker-compose.yml up --build

# 4. Verify health
curl http://localhost:8000/health

# 5. POST a sample email
curl -X POST http://localhost:8000/api/v1/emails/ingest \
  -H 'Content-Type: application/json' \
  -d @infra/samples/medium_risk_email.json

# 6. Open the analyst queue
open http://localhost:3000
```

## Architecture

```
POST /api/v1/emails/ingest
       │
       ▼
  DetectionService
  ├── HeaderAnalyzer    (SPF/DKIM/DMARC, reply-to mismatch, lookalike display-name)
  ├── ContentAnalyzer   (urgency/credential rules + ML classifier)
  ├── URLAnalyzer       (RDAP age, redirect chain, lookalike domains, credential harvest)
  ├── QRCodeDetector    (image extraction → pyzbar → URLAnalyzer)
  └── ThreatIntelModule (local blocklist; external feed = stub)
       │
       ▼
  ScoringEngine  →  ScoreResult (0–100, tier, verdict, explanation)
       │
       ▼
  PostgreSQL (phishdetect schema) + Redis queue
       │
       ▼
  Analyst Review Queue  →  Verdict  →  FeedbackEvent (→ Layer 2 stub)
```

## Key Invariants (enforced in code)

| Rule | Where |
|---|---|
| No single signal independently blocks | `ScoringConfig.validate_invariant()` + `test_scoring_invariant.py` |
| No quarantine without explanation | `explanation` is non-optional on `EmailAnalysisResponse` |
| Feedback loop contract in place | `FeedbackEvent` + `feedback_events` table |
| Phase 3 not built | No behavioural baselines, relationship graphs, or OAuth monitoring |

## Project Layout

```
infra/          Docker Compose, env template, sample fixtures
services/       FastAPI detection pipeline (Python)
  app/
    api/        Thin route controllers
    detectors/  header, content, url, qrcode, threat_intel, domain_intel
    scoring/    ScoringConfig + ScoringEngine (invariant here)
    services/   DetectionService, VerdictService, QueueService
    models/     SQLAlchemy ORM (phishdetect schema)
    schemas/    Pydantic schemas
  tests/        Pytest — scoring invariant runs first in CI
  alembic/      DB migrations (owns all DDL)
ml/             Training script, inference wrapper, governance doc
frontend/       Vite + React + MUI analyst dashboard
.claude/context/ Modular context files (read before coding)
```

## Running Tests

```bash
cd services
pip install -r requirements.txt
pytest tests/test_scoring_invariant.py -v          # invariant — must pass
pytest tests/ -v --cov=app --cov-report=term-missing
```

## ML Dataset

**Phishing class:** [phishing_pot](https://github.com/rf-peixoto/phishing_pot) — 8,614 real phishing `.eml`  
**Ham class:** [Enron-spam](http://www.aueb.gr/users/ion/data/enron-spam/) — download and extract to `ml/data/enron_ham/`

See `ml/governance.md` for retraining process and drift monitoring.
