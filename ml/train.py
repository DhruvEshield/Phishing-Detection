"""
ML content classifier training script.

Dataset: phishing_pot (8,614 phishing .eml, vendored at ml/data/phishing_pot/email/)
         + Enron-ham (legitimate emails — download instructions below)

NOTE: This trains a TF-IDF + Logistic Regression baseline.
      The ContentClassifier interface in inference.py is swappable — replace with
      a fine-tuned transformer without changing the backend detector.

Usage:
    python ml/train.py

Outputs (gitignored):
    ml/models/content_classifier_<version>/model.joblib
    ml/models/content_classifier_<version>/vectorizer.joblib
    ml/models/content_classifier_<version>/metadata.json
    ml/reports/eval_<version>.json
"""
from __future__ import annotations

import email
import json
import os
import glob
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
from sklearn.pipeline import Pipeline

# ── Config ───────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
PHISHING_DIR = BASE_DIR / "data" / "phishing_pot" / "email"
# Enron ham: download from http://www.aueb.gr/users/ion/data/enron-spam/
# and extract to ml/data/enron_ham/
ENRON_HAM_DIR = BASE_DIR / "data" / "enron_ham"
MODEL_VERSION = os.getenv("MODEL_VERSION", "v0.1.0")
MODELS_DIR = BASE_DIR / "models" / f"content_classifier_{MODEL_VERSION}"
REPORTS_DIR = BASE_DIR / "reports"
MAX_FEATURES = 50_000
MAX_ITER = 1000


def _extract_text_from_eml(path: str) -> str:
    """Parse a .eml file and return its plain-text body."""
    try:
        with open(path, "rb") as f:
            msg = email.message_from_bytes(f.read())
        parts = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        parts.append(part.get_payload(decode=True).decode(
                            part.get_content_charset() or "utf-8", errors="replace"
                        ))
                    except Exception:
                        pass
        else:
            try:
                parts.append(msg.get_payload(decode=True).decode(
                    msg.get_content_charset() or "utf-8", errors="replace"
                ))
            except Exception:
                pass
        subject = msg.get("Subject", "")
        return f"{subject} {' '.join(parts)}"
    except Exception as exc:
        print(f"[WARN] Failed to parse {path}: {exc}")
        return ""


def load_phishing(limit: int | None = None) -> list[str]:
    paths = glob.glob(str(PHISHING_DIR / "*.eml"))
    if limit:
        paths = paths[:limit]
    print(f"[INFO] Loading {len(paths)} phishing emails from phishing_pot")
    return [t for p in paths if (t := _extract_text_from_eml(p))]


def load_ham(limit: int | None = None) -> list[str]:
    """Load Enron ham emails. Falls back to synthetic samples if dir not present."""
    if ENRON_HAM_DIR.exists():
        paths = glob.glob(str(ENRON_HAM_DIR / "**/*.eml"), recursive=True)
        if limit:
            paths = paths[:limit]
        print(f"[INFO] Loading {len(paths)} ham emails from Enron")
        return [t for p in paths if (t := _extract_text_from_eml(p))]
    else:
        print(
            "[WARN] Enron ham directory not found at ml/data/enron_ham/. "
            "Using synthetic placeholder samples. "
            "Download from: http://www.aueb.gr/users/ion/data/enron-spam/ "
            "and extract to ml/data/enron_ham/ for production quality."
        )
        return [
            "Hi, are you free for a meeting tomorrow?",
            "Please find attached the quarterly report.",
            "Let's catch up for coffee on Friday.",
            "The project deadline has been moved to next week.",
            "I've reviewed your proposal and have some feedback.",
            "Great work on the presentation yesterday!",
            "Can you send me the updated spreadsheet?",
            "The conference call is scheduled for 3pm.",
        ] * 500  # inflate synthetic samples


def main():
    # Load data
    phishing = load_phishing()
    ham = load_ham()

    if not phishing:
        raise RuntimeError(
            "No phishing emails found. "
            f"Expected .eml files at: {PHISHING_DIR}\n"
            "Run: git clone https://github.com/rf-peixoto/phishing_pot && "
            "cp -r phishing_pot/email ml/data/phishing_pot/"
        )

    texts = phishing + ham
    labels = ["phishing"] * len(phishing) + ["legitimate"] * len(ham)

    print(f"[INFO] Dataset: {len(phishing)} phishing, {len(ham)} legitimate")

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels,
    )

    # ── Build pipeline ────────────────────────────────────────────────────────
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=MAX_FEATURES,
            ngram_range=(1, 2),
            sublinear_tf=True,
            strip_accents="unicode",
            analyzer="word",
            min_df=2,
        )),
        ("clf", LogisticRegression(
            C=1.0, class_weight="balanced", max_iter=MAX_ITER, n_jobs=-1,
        )),
    ])

    print("[INFO] Training TF-IDF + LogisticRegression pipeline...")
    pipeline.fit(X_train, y_train)

    # ── Evaluate ──────────────────────────────────────────────────────────────
    y_pred = pipeline.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)
    f1 = f1_score(y_test, y_pred, pos_label="phishing")
    print(f"[INFO] F1 (phishing): {f1:.4f}")
    print(classification_report(y_test, y_pred))

    # ── Save ──────────────────────────────────────────────────────────────────
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(pipeline, MODELS_DIR / "pipeline.joblib")

    metadata = {
        "version": MODEL_VERSION,
        "algorithm": "TF-IDF + LogisticRegression",
        "dataset": {
            "phishing": "phishing_pot (rf-peixoto/phishing_pot)",
            "ham": "enron-spam or synthetic",
            "train_size": len(X_train),
            "test_size": len(X_test),
        },
        "metrics": {"f1_phishing": round(f1, 4), "report": report},
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "max_features": MAX_FEATURES,
    }
    with open(MODELS_DIR / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    report_path = REPORTS_DIR / f"eval_{MODEL_VERSION}.json"
    with open(report_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[OK] Model saved to {MODELS_DIR}")
    print(f"[OK] Evaluation report: {report_path}")


if __name__ == "__main__":
    main()
