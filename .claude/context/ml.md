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

## Stack (intended direction — pin versions as code lands)

- **NLP / content classification:** scikit-learn for baselines; spaCy / Hugging Face
  Transformers (PyTorch) for the production classifier.
- **Anomaly detection:** scikit-learn (e.g. IsolationForest) initially; revisit per data volume.
- **Graph analysis:** NetworkX for modelling; a graph store (e.g. Neo4j) if/when scale demands.
- **Computer vision (QR):** OpenCV + a QR decoder (e.g. `pyzbar` / OpenCV QR detector).

## Governance guardrail (enforce in code AND process)

Classification and anomaly models **drift**. All AI-driven decisions stay **subject to analyst
review and periodic retraining** — never fully automated enforcement. Build for
human-in-the-loop, explainability, and retraining **from day one**. Treat every model as a
maintained asset with a retraining path, not a one-time artifact.

> Phase note: the content classifier and QR extraction are Phase 1. Behavioural anomaly and
> relationship graph are **Phase 3** — they need accumulated history to avoid high false
> positives. Don't build them before Phase 1's data pipeline exists. See [roadmap.md](roadmap.md).
