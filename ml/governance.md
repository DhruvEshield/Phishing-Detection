# ML Governance — Content Classifier

> Owned by: ml.md  
> Required by: principles.md #9 (models drift — plan for retraining)  
> CLAUDE.md rule: "all AI-driven decisions remain subject to analyst review and periodic retraining"

---

## Model: Content Classifier (TF-IDF + Logistic Regression baseline)

**Version scheme:** `v<major>.<minor>.<patch>` — bumped on every retrain.  
**Version tracking:** stored in `AnalysisResult.model_version` so every production decision is traceable to the model that made it.

---

## Retraining Triggers

Retrain when **any** of the following is true:

| Signal | Threshold | Source |
|---|---|---|
| F1 (phishing class) on monthly eval | Drops > 5 points absolute | `ml/evaluate.py` output |
| Analyst override rate | > 20% of ML-flagged emails reversed in 30 days | `feedback_events` table |
| New attack variant identified | Qualitative — security team flags a blind spot | Analyst / threat intel |
| Corpus staleness | > 6 months since last retrain with fresh phishing_pot snapshot | Calendar |

---

## Retraining Process

1. **Pull new data:** export analyst-labelled emails from `feedback_events` where `action='quarantine'` (confirmed phishing) or `action='approve'` (confirmed legitimate). Also pull latest phishing_pot snapshot.
2. **Combine:** merge new analyst-labelled data with existing training corpus. Keep a versioned snapshot at `ml/data/train_<date>/`.
3. **Retrain:** `python ml/train.py` — outputs to `ml/models/content_classifier_<new_version>/`.
4. **Evaluate:** `python ml/evaluate.py` — must show F1 ≥ previous version's F1 - 2pp on held-out test set.
5. **Human approval gate:** a security team member reviews the eval report in `ml/reports/`. No automated deployment of a new model version.
6. **Deploy:** update `MODEL_VERSION` env var in `.env` / Docker Compose. Restart API service. New version starts appearing in `AnalysisResult.model_version`.
7. **Monitor:** watch analyst override rate in the first 14 days post-deploy. Roll back if > 25%.

---

## Drift Monitoring

- **Monthly eval job** (manual in Phase 1; automated script in Phase 2): run `python ml/evaluate.py` on the last 30 days of analyst-labelled data.
- **Override rate query** (run monthly):
  ```sql
  SELECT
    action,
    COUNT(*) as count,
    COUNT(*) * 100.0 / SUM(COUNT(*)) OVER () AS pct
  FROM phishdetect.verdicts
  WHERE created_at > NOW() - INTERVAL '30 days'
  GROUP BY action;
  ```
  If quarantine overrides (approve after ML flagged) > 20%: trigger retrain.

---

## What a Future Transformer Upgrade Looks Like

The `ContentClassifier` interface in `ml/inference.py` is the only contract the backend sees.  
To upgrade to a fine-tuned transformer:
1. Fine-tune (e.g., DistilBERT on phishing_pot + ham).
2. Implement a new class with the same `.predict(text) -> ClassificationResult` signature.
3. Update `ContentClassifier.load()` to load the new model format.
4. Bump `MODEL_VERSION`. No changes to `services/`.

---

## Scope Note

Behavioural anomaly detection and relationship graph models are **Phase 3** — they require accumulated communication history. Do not train them before Phase 1's data pipeline has been running long enough to build reliable baselines (see roadmap.md).
