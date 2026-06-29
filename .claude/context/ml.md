# ML — Models, Training, Retraining (`ml/`)

> Load this when working in `ml/` — model code, training, evaluation, and retraining pipelines.
>
> **Skills:** `tdd-workflow` (test data transforms and inference paths).

## Principle: ML is one tool, not the approach

Prefer rules/heuristics where they suffice; reach for ML only where data volume, contextual
pattern recognition, or attacker evolution makes rules insufficient. (See
[principles.md](principles.md) #1 and #9.) The backend ([backend.md](backend.md)) consumes
model outputs as weighted signals — it does not train them.

## The four ML components (and why ML over rules)

| Component | Technique | Why ML (not rules) |
|---|---|---|
| Content analysis | NLP text classification | Generalises to new phrasing, languages, AI-generated content; scales to thousands of emails/min |
| Behavioural analysis | Anomaly detection | Builds per-user baselines automatically; "anomalous" differs per user |
| Relationship analysis | Graph-based modelling | Detects structural anomalies (a lookalike node inserting into a trusted cluster) invisible to content scanning |
| QR extraction | Computer vision | QR images can't be read by text parsers; narrow, well-defined image task |

## Stack (confirmed — Phase 1 built)
- **Content classifier:** TF-IDF + Logistic Regression (scikit-learn 1.6.1). Swappable via `ContentClassifier` interface in `ml/inference.py`.
- **QR extraction:** OpenCV + pyzbar. Built into `QRCodeDetector` in the backend.
- **Behavioural anomaly + relationship graph:** Phase 3 — not built yet.

## Content classifier — what's built
| Item | Detail |
|---|---|
| Algorithm | TF-IDF vectorisation + Logistic Regression |
| Training data | 8,612 phishing emails (phishing_pot) + 15,553 legitimate emails (SetFit/enron_spam, Hugging Face) |
| Accuracy | 99% |
| F1 (phishing) | 0.986 |
| Model version | v0.1.0 |
| Model location | `ml/models/content_classifier_v0.1.0/pipeline.joblib` (gitignored) |

## Files
- `ml/train.py` — training script, auto-downloads ham dataset from Hugging Face on first run
- `ml/inference.py` — `ContentClassifier` interface, loads versioned model, exposes `predict(text)`
- `ml/evaluate.py` — standalone evaluation script, runs trained model against full dataset
- `ml/governance.md` — retraining triggers, process, and drift monitoring plan
- `ml/models/` — gitignored, built by `train.py`
- `ml/reports/` — gitignored, written by `train.py` and `evaluate.py`
- `ml/data/phishing_pot/email/` — 8,612 real phishing .eml files (gitignored, large)
- `ml/data/ham/` — downloaded ham emails (gitignored, auto-downloaded by train.py)

## Retraining triggers (from governance.md)
- F1 drops > 5% on monthly eval
- Analyst override rate > 20% over 30 days
- Manual approval gate before deploying new version

## Governance guardrail
All ML decisions stay subject to analyst review — never fully automated enforcement. Every model version is tracked in `AnalysisResult.model_version` so drift is visible from production data.
