"""
Model diagnostic — reveals WHAT the classifier learned, not just how well it
scores its own corpus. Two probes:

  1. Top features   — the tokens with the largest phishing / legitimate weights.
                      If 'legitimate' is defined by Enron-era artifacts (names,
                      years, corporate jargon) rather than genuine non-phishing
                      cues, this exposes it directly.
  2. OOD probe      — hand-written MODERN emails the model never saw. The failure
                      mode we care about: ordinary modern legit mail flagged as
                      phishing because it doesn't look like 2001 Enron.

Usage:  ml/.venv/bin/python ml/diagnose.py
"""
from __future__ import annotations

import os
from pathlib import Path

import joblib

from text_normalize import normalize_text
from eval_samples import LEGIT_MODERN, PHISH_MODERN

BASE_DIR = Path(__file__).parent
MODEL_VERSION = os.getenv("MODEL_VERSION", "v0.2.0")
MODELS_DIR = BASE_DIR / "models" / f"content_classifier_{MODEL_VERSION}"


def top_features(pipeline, n=30):
    tfidf = pipeline.named_steps["tfidf"]
    clf = pipeline.named_steps["clf"]
    names = tfidf.get_feature_names_out()
    coef = clf.coef_[0]
    # coef_[0] aligns with positive class = clf.classes_[1] (alphabetical -> 'phishing')
    pos_class = clf.classes_[1]
    order = coef.argsort()
    print(f"\n[coef_[0] positive class = '{pos_class}']")
    print(f"\n=== Top {n} tokens pushing toward PHISHING ===")
    for i in reversed(order[-n:]):
        print(f"  {coef[i]:+.3f}  {names[i]}")
    print(f"\n=== Top {n} tokens pushing toward LEGITIMATE ===")
    for i in order[:n]:
        print(f"  {coef[i]:+.3f}  {names[i]}")


def ood_probe(pipeline):
    classes = pipeline.classes_.tolist()
    pidx = classes.index("phishing")

    def score(text):
        return float(pipeline.predict_proba([normalize_text(text)])[0][pidx])

    print("\n=== OOD probe: MODERN LEGIT (want low phishing prob) ===")
    fp = 0
    for name, text in LEGIT_MODERN:
        p = score(text)
        flag = "  <-- FALSE POSITIVE" if p >= 0.5 else ""
        if p >= 0.5:
            fp += 1
        print(f"  phish_prob={p:.3f}  {name}{flag}")
    print(f"  -> {fp}/{len(LEGIT_MODERN)} modern-legit emails misflagged as phishing")

    print("\n=== OOD probe: MODERN PHISHING (want high phishing prob) ===")
    fn = 0
    for name, text in PHISH_MODERN:
        p = score(text)
        flag = "  <-- MISSED" if p < 0.5 else ""
        if p < 0.5:
            fn += 1
        print(f"  phish_prob={p:.3f}  {name}{flag}")
    print(f"  -> {fn}/{len(PHISH_MODERN)} modern-phishing emails missed")


def main():
    pipeline = joblib.load(MODELS_DIR / "pipeline.joblib")
    top_features(pipeline)
    ood_probe(pipeline)


if __name__ == "__main__":
    main()
