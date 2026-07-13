"""ML inference wrapper — ContentClassifier interface.

This is the boundary between the backend detector (services/app/detectors/content.py)
and the trained model. The backend imports only this interface — it never touches
sklearn directly. Swap the underlying model by modifying this file alone.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import joblib
import structlog

from text_normalize import normalize_text

log = structlog.get_logger()


@dataclass
class ClassificationResult:
    label: str          # "phishing" or "legitimate"
    confidence: float   # 0–1
    model_version: str


class ContentClassifier:
    """
    Wraps the trained TF-IDF + LR pipeline.

    Usage:
        clf = ContentClassifier.load("ml/models", "v0.1.0")
        result = clf.predict("Your account is suspended. Click here.")
    """

    def __init__(self, pipeline, metadata: dict, model_version: str):
        self._pipeline = pipeline
        self._metadata = metadata
        self._version = model_version

    @classmethod
    def load(cls, model_path: str, version: str) -> "ContentClassifier":
        model_dir = Path(model_path) / f"content_classifier_{version}"
        pipeline_path = model_dir / "pipeline.joblib"
        meta_path = model_dir / "metadata.json"

        if not pipeline_path.exists():
            raise FileNotFoundError(
                f"Model not found at {pipeline_path}. "
                f"Run `python ml/train.py` to train the model first."
            )

        pipeline = joblib.load(pipeline_path)
        metadata = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        log.info("classifier.loaded", version=version, path=str(model_dir))
        return cls(pipeline, metadata, version)

    def predict(self, text: str) -> ClassificationResult:
        """
        Predict whether the text is phishing or legitimate.
        Returns ClassificationResult with label, confidence, and model_version.
        Every score is traceable to this version (stored in AnalysisResult.model_version).
        """
        if not text.strip():
            return ClassificationResult(
                label="legitimate", confidence=1.0, model_version=self._version
            )

        # Same normalization used at training time (ml/train.py). Must match, or
        # the model sees a different distribution in production than it learned.
        normalized = normalize_text(text)
        if not normalized:
            return ClassificationResult(
                label="legitimate", confidence=1.0, model_version=self._version
            )

        proba = self._pipeline.predict_proba([normalized])[0]
        classes = self._pipeline.classes_.tolist()
        phish_idx = classes.index("phishing")
        confidence = float(proba[phish_idx])
        label = "phishing" if confidence >= 0.5 else "legitimate"

        return ClassificationResult(
            label=label,
            confidence=confidence if label == "phishing" else 1.0 - confidence,
            model_version=self._version,
        )

    @property
    def metadata(self) -> dict:
        return self._metadata
