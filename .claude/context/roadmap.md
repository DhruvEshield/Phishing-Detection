# Roadmap — Phases

> Load this to decide *what to build next* or to check whether a request is in-phase.
> **Progression is evidence-driven, not schedule-driven** — advance on what the data shows.
>
> **Current phase: Phase 1.** If asked to build Phase 2/3 work before Phase 1's data pipeline
> exists, call it out (baselines on thin data → high false positives → lost analyst trust).

## Phase 1 — Core Email Analysis *(start here)*

**Focus:** strengthen pre-delivery, email-level detection of traditional + QR phishing.
**Capabilities:**
- Header analysis (SPF / DKIM / DMARC validation + heuristics)
- Content analysis via NLP classification
- URL scanning (domain age/WHOIS, threat intel, link inspection)
- Basic QR-code extraction & decoding → URL pipeline
- Threat-intelligence integration
- **Risk-scoring engine + tiered routing** (quarantine / review / deliver)
- **The analyst feedback loop and data pipeline** — the foundation everything else builds on.

**Key risk:** cold start — no historical baselines yet. Design data capture now so Phase 3
has history.
**Definition of done:** measurable detection of traditional + QR phishing pre-delivery, with an
analyst review queue and stored verdicts feeding a retrainable corpus.

## Phase 2 — Advanced Threat Detection

**Trigger:** Phase 1 data reveals where sophisticated campaigns slip through.
**Focus:** coverage for advanced campaigns + analyst trust via explainability.
**Capabilities:**
- Sandbox detonation for suspicious URLs/attachments (**scoped** — cost-aware, not everything)
- Enhanced QR phishing analysis
- **Explainability layer** (why an email was flagged) — analysts must trust decisions before
  scope expands
- Analyst dashboard
- Expanded threat-intel correlation

**Key risk:** sandbox infrastructure cost — scope detonation carefully.

## Phase 3 — Behavioural & Identity Intelligence

**Trigger:** enough communication history for reliable baselines + stakeholder alignment on
data governance.
**Focus:** Layer 2 — BEC, VEC, thread hijacking, account compromise, OAuth abuse, identity attacks.
**Capabilities:**
- Behavioural analytics (per-user anomaly detection)
- Relationship-intelligence / graph analysis
- Model retraining pipeline
- Retroactive review of already-delivered email on confirmed compromise

**Key risk:** data governance — behavioural/identity monitoring needs email + account metadata;
engage stakeholders early.
