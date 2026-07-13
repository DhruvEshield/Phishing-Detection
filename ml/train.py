"""
ML content classifier training script (v0.2.0 pipeline).

Dataset
-------
  phishing : phishing_pot .eml           (rf-peixoto/phishing_pot, ~8.6k)
  ham      : Enron-spam ham .txt          (subsampled for balance/diversity)
           + SpamAssassin easy/hard ham   (real .eml, incl. HTML newsletters)

Every source is parsed through the SAME normalizer (ml/text_normalize.py):
Subject+body only, HTML stripped, URLs/emails/dates/numbers masked. This kills
the v0.1.0 artifacts (the `phishing@pot` honeypot leak, header/date tokens,
modern-year and HTML-vs-plaintext separation) so the model must learn content.

Honesty checks printed every run:
  - standard held-out test report (dedup'd, stratified)
  - per-SOURCE accuracy on the test set (is any single source trivially learned?)
  - modern-legit FALSE-POSITIVE rate on a curated OOD guard set (ml/eval_samples.py)

Usage:  ml/.venv/bin/python ml/train.py
"""
from __future__ import annotations

import glob
import json
import os
import random
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
from sklearn.pipeline import Pipeline

from text_normalize import from_eml_file, from_enron_txt, normalize_text
from eval_samples import LEGIT_MODERN, PHISH_MODERN

# ── Config ───────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
PHISHING_DIR = BASE_DIR / "data" / "phishing_pot" / "email"
ENRON_HAM_DIR = BASE_DIR / "data" / "ham"
SA_HAM_DIR = BASE_DIR / "data" / "spamassassin_ham"
MODERN_HAM_DIR = BASE_DIR / "data" / "modern_ham"
MODEL_VERSION = os.getenv("MODEL_VERSION", "v0.2.0")
MODELS_DIR = BASE_DIR / "models" / f"content_classifier_{MODEL_VERSION}"
REPORTS_DIR = BASE_DIR / "reports"
MAX_FEATURES = 50_000
MAX_ITER = 1000
ENRON_CAP = 8_000       # subsample Enron so it doesn't dominate / monopolise ham
SEED = 42


# ── Loading (returns (text, source) tuples) ──────────────────────────────────
def load_phishing() -> list[tuple[str, str]]:
    paths = sorted(glob.glob(str(PHISHING_DIR / "*.eml")))
    out = [(t, "phishing_pot") for p in paths if (t := from_eml_file(p))]
    print(f"[INFO] phishing_pot: {len(out)} usable")
    return out


def load_ham() -> list[tuple[str, str]]:
    ham: list[tuple[str, str]] = []

    enron = sorted(glob.glob(str(ENRON_HAM_DIR / "*.txt")))
    rng = random.Random(SEED)
    rng.shuffle(enron)
    enron = enron[:ENRON_CAP]
    enron_texts = [(t, "enron") for p in enron if (t := from_enron_txt(p))]
    print(f"[INFO] enron ham: {len(enron_texts)} usable (capped at {ENRON_CAP})")
    ham += enron_texts

    if SA_HAM_DIR.exists():
        sa_paths = [p for p in SA_HAM_DIR.rglob("*")
                    if p.is_file() and p.name != "cmds"]
        sa_texts = [(t, "spamassassin") for p in sa_paths if (t := from_eml_file(p))]
        print(f"[INFO] spamassassin ham: {len(sa_texts)} usable")
        ham += sa_texts
    else:
        print("[WARN] SpamAssassin ham dir missing — Enron-only ham")

    if MODERN_HAM_DIR.exists():
        modern = sorted(glob.glob(str(MODERN_HAM_DIR / "*.txt")))
        modern_texts = [(t, "modern") for p in modern if (t := from_enron_txt(p))]
        print(f"[INFO] modern (synthetic) ham: {len(modern_texts)} usable")
        ham += modern_texts
    else:
        print("[WARN] modern ham dir missing — run data/gen_modern_ham.py")

    return ham


def dedup(rows: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """Drop empty and exact-duplicate normalized texts (prevents train/test leak)."""
    seen: set[str] = set()
    out = []
    for text, label, source in rows:
        if len(text.split()) < 3:      # too short to be meaningful
            continue
        if text in seen:
            continue
        seen.add(text)
        out.append((text, label, source))
    return out


def guard_report(pipeline) -> dict:
    classes = pipeline.classes_.tolist()
    pidx = classes.index("phishing")

    def phish_prob(raw: str) -> float:
        return float(pipeline.predict_proba([normalize_text(raw)])[0][pidx])

    legit = [(n, phish_prob(t)) for n, t in LEGIT_MODERN]
    phish = [(n, phish_prob(t)) for n, t in PHISH_MODERN]
    fp = sum(1 for _, p in legit if p >= 0.5)
    fn = sum(1 for _, p in phish if p < 0.5)
    print("\n[GUARD] modern-legit (want < 0.5):")
    for n, p in legit:
        print(f"        {p:.3f}  {n}{'  <-- FALSE POSITIVE' if p >= 0.5 else ''}")
    print("[GUARD] modern-phishing (want >= 0.5):")
    for n, p in phish:
        print(f"        {p:.3f}  {n}{'  <-- MISSED' if p < 0.5 else ''}")
    print(f"[GUARD] modern-legit FP: {fp}/{len(legit)}   modern-phish missed: {fn}/{len(phish)}")
    return {
        "modern_legit_fp": f"{fp}/{len(legit)}",
        "modern_phish_missed": f"{fn}/{len(phish)}",
        "legit_probs": {n: round(p, 3) for n, p in legit},
        "phish_probs": {n: round(p, 3) for n, p in phish},
    }


def main():
    rows = [(t, "phishing", s) for t, s in load_phishing()] + \
           [(t, "legitimate", s) for t, s in load_ham()]
    rows = dedup(rows)

    if not any(l == "phishing" for _, l, _ in rows):
        raise RuntimeError(f"No phishing emails parsed from {PHISHING_DIR}")

    texts = [r[0] for r in rows]
    labels = [r[1] for r in rows]
    sources = [r[2] for r in rows]

    n_phish = labels.count("phishing")
    n_ham = labels.count("legitimate")
    print(f"\n[INFO] Dataset after dedup: {n_phish} phishing, {n_ham} legitimate")
    from collections import Counter
    print(f"[INFO] Sources: {dict(Counter(sources))}")

    idx = list(range(len(texts)))
    tr, te = train_test_split(idx, test_size=0.2, random_state=SEED,
                              stratify=labels)
    X_train = [texts[i] for i in tr]
    y_train = [labels[i] for i in tr]
    X_test = [texts[i] for i in te]
    y_test = [labels[i] for i in te]
    src_test = [sources[i] for i in te]

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=MAX_FEATURES, ngram_range=(1, 2), sublinear_tf=True,
            strip_accents="unicode", analyzer="word", min_df=2,
        )),
        ("clf", LogisticRegression(
            C=1.0, class_weight="balanced", max_iter=MAX_ITER, n_jobs=1,
        )),
    ])

    print("[INFO] Training TF-IDF + LogisticRegression...")
    pipeline.fit(X_train, y_train)

    # ── Evaluate ──────────────────────────────────────────────────────────────
    y_pred = pipeline.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)
    f1 = f1_score(y_test, y_pred, pos_label="phishing")
    print(f"\n[INFO] Held-out F1 (phishing): {f1:.4f}")
    print(classification_report(y_test, y_pred))

    # per-source accuracy on the test set
    print("[INFO] Per-source test accuracy:")
    per_source = {}
    for s in sorted(set(src_test)):
        pairs = [(yt, yp) for yt, yp, ss in zip(y_test, y_pred, src_test) if ss == s]
        acc = sum(1 for yt, yp in pairs if yt == yp) / len(pairs)
        per_source[s] = {"n": len(pairs), "accuracy": round(acc, 4)}
        print(f"        {s:14s} n={len(pairs):5d}  acc={acc:.4f}")

    guard = guard_report(pipeline)

    # ── Save ──────────────────────────────────────────────────────────────────
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODELS_DIR / "pipeline.joblib")

    metadata = {
        "version": MODEL_VERSION,
        "algorithm": "TF-IDF + LogisticRegression (normalized text)",
        "preprocessing": "text_normalize.normalize_text (subject+body, HTML stripped, url/email/num masked)",
        "dataset": {
            "phishing": "phishing_pot",
            "ham": "enron (capped) + spamassassin easy/hard",
            "sources": dict(Counter(sources)),
            "train_size": len(X_train),
            "test_size": len(X_test),
        },
        "metrics": {
            "f1_phishing": round(f1, 4),
            "report": report,
            "per_source_test": per_source,
            "modern_guard": guard,
        },
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "max_features": MAX_FEATURES,
    }
    (MODELS_DIR / "metadata.json").write_text(json.dumps(metadata, indent=2))
    (REPORTS_DIR / f"eval_{MODEL_VERSION}.json").write_text(json.dumps(metadata, indent=2))

    print(f"\n[OK] Model saved to {MODELS_DIR}")


if __name__ == "__main__":
    main()
