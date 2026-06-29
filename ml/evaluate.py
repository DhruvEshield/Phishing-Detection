"""
Standalone evaluation script — runs the trained model against a test set
without retraining. Outputs precision, recall, F1 to ml/reports/.

Usage:
    python ml/evaluate.py

Requires:
    - Trained model at ml/models/content_classifier_<version>/pipeline.joblib
    - Run ml/train.py first if model doesn't exist
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.metrics import classification_report, f1_score

BASE_DIR = Path(__file__).parent
MODEL_VERSION = os.getenv("MODEL_VERSION", "v0.1.0")
MODELS_DIR = BASE_DIR / "models" / f"content_classifier_{MODEL_VERSION}"
REPORTS_DIR = BASE_DIR / "reports"
HAM_DIR = BASE_DIR / "data" / "ham"
PHISHING_DIR = BASE_DIR / "data" / "phishing_pot" / "email"


def load_texts_and_labels() -> tuple[list[str], list[str]]:
    """Load phishing and ham texts with labels."""
    import glob
    import email as email_lib

    def read_eml(path: str) -> str:
        try:
            with open(path, "rb") as f:
                msg = email_lib.message_from_bytes(f.read())
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
            return f"{msg.get('Subject', '')} {' '.join(parts)}"
        except Exception as exc:
            print(f"[WARN] Failed to parse {path}: {exc}")
            return ""

    phishing_paths = glob.glob(str(PHISHING_DIR / "*.eml"))
    phishing_texts = [t for p in phishing_paths if (t := read_eml(p))]

    ham_texts = []
    if HAM_DIR.exists():
        for path in HAM_DIR.glob("*.txt"):
            try:
                ham_texts.append(path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                pass

    texts = phishing_texts + ham_texts
    labels = ["phishing"] * len(phishing_texts) + ["legitimate"] * len(ham_texts)
    print(f"[INFO] Loaded {len(phishing_texts)} phishing, {len(ham_texts)} legitimate")
    return texts, labels


def main():
    pipeline_path = MODELS_DIR / "pipeline.joblib"
    if not pipeline_path.exists():
        raise FileNotFoundError(
            f"No trained model found at {pipeline_path}. "
            "Run python ml/train.py first."
        )

    print(f"[INFO] Loading model from {MODELS_DIR}")
    pipeline = joblib.load(pipeline_path)

    texts, labels = load_texts_and_labels()
    if not texts:
        raise RuntimeError("No data found. Check ml/data/ directories.")

    print("[INFO] Running evaluation...")
    predictions = pipeline.predict(texts)
    f1 = f1_score(labels, predictions, pos_label="phishing")
    report = classification_report(labels, predictions, output_dict=True)

    print(f"[INFO] F1 (phishing): {f1:.4f}")
    print(classification_report(labels, predictions))

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORTS_DIR / f"eval_standalone_{MODEL_VERSION}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w") as f:
        json.dump({
            "version": MODEL_VERSION,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "metrics": {"f1_phishing": round(f1, 4), "report": report},
        }, f, indent=2)

    print(f"[OK] Evaluation report saved to {report_path}")


if __name__ == "__main__":
    main()
