"""
Tests for the ContentClassifier inference wrapper.

The wrapper is the *only* boundary the backend detector touches, so its contract
matters more than the model internals: empty/blank input must short-circuit to a
confident "legitimate" (never crash a pipeline), the phishing-vs-legitimate
threshold is 0.5, and confidence is always reported for the *predicted* class.

Most tests inject a fake pipeline so they assert the wrapper's logic
deterministically, independent of whichever model artifact is on disk. One test
loads the real committed model if present (skipped otherwise).
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from inference import ClassificationResult, ContentClassifier


class FakePipeline:
    """Stand-in for the sklearn Pipeline: records inputs, returns fixed proba."""

    def __init__(self, phish_proba: float):
        # sklearn orders classes_ alphabetically: [legitimate, phishing].
        self.classes_ = np.array(["legitimate", "phishing"])
        self._phish = phish_proba
        self.seen: list[list[str]] = []

    def predict_proba(self, texts):
        self.seen.append(list(texts))
        return np.array([[1.0 - self._phish, self._phish]])


def make_clf(phish_proba: float, version: str = "vTest") -> ContentClassifier:
    return ContentClassifier(FakePipeline(phish_proba), {"trained_on": "fake"}, version)


class TestPredictShortCircuits:
    def test_empty_string_is_legitimate_without_calling_pipeline(self):
        clf = make_clf(0.99)
        res = clf.predict("")
        assert res.label == "legitimate"
        assert res.confidence == 1.0
        assert res.model_version == "vTest"
        assert clf._pipeline.seen == []  # pipeline never touched

    def test_whitespace_only_is_legitimate(self):
        clf = make_clf(0.99)
        res = clf.predict("   \n\t ")
        assert res.label == "legitimate"
        assert clf._pipeline.seen == []

    def test_text_that_normalizes_to_empty_is_legitimate(self):
        # 'enron'/'vince' are leakage stopwords dropped by the normalizer, so
        # this input reduces to "" and must short-circuit, not hit the model.
        clf = make_clf(0.99)
        res = clf.predict("enron vince enron")
        assert res.label == "legitimate"
        assert res.confidence == 1.0
        assert clf._pipeline.seen == []


class TestPredictThreshold:
    def test_high_phish_proba_labels_phishing_with_that_confidence(self):
        res = make_clf(0.92).predict("your account is suspended, verify now")
        assert res.label == "phishing"
        assert res.confidence == pytest.approx(0.92)

    def test_low_phish_proba_labels_legitimate_with_complement_confidence(self):
        res = make_clf(0.10).predict("lunch tomorrow at the usual place")
        assert res.label == "legitimate"
        # confidence is reported for the *predicted* class => 1 - 0.10
        assert res.confidence == pytest.approx(0.90)

    def test_exactly_half_is_phishing(self):
        res = make_clf(0.50).predict("some borderline message")
        assert res.label == "phishing"
        assert res.confidence == pytest.approx(0.50)

    def test_model_version_is_propagated(self):
        res = make_clf(0.8, version="v9.9.9").predict("verify your password")
        assert res.model_version == "v9.9.9"


class TestNormalizationApplied:
    def test_pipeline_receives_masked_text_not_raw_identities(self):
        clf = make_clf(0.7)
        clf.predict("Click http://evil.example/verify or email a@b.com now")
        (sent,) = clf._pipeline.seen  # exactly one predict_proba call
        text = sent[0]
        # identities masked to placeholders before the model sees them
        assert "evil" not in text and "a@b.com" not in text
        assert "url" in text.split() and "email" in text.split()


class TestMetadata:
    def test_metadata_is_exposed(self):
        clf = make_clf(0.5)
        assert clf.metadata == {"trained_on": "fake"}


class TestLoad:
    def test_missing_model_raises_filenotfound(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ContentClassifier.load(str(tmp_path), "v0.0.0")

    def test_loads_and_predicts_with_real_model_if_present(self):
        # Integration check against the committed artifact. Skips cleanly when the
        # joblib is absent (e.g. only metadata.json is committed for a version).
        model_root = Path(__file__).resolve().parents[1] / "models"
        v010 = model_root / "content_classifier_v0.1.0" / "pipeline.joblib"
        if not v010.exists():
            pytest.skip("real model artifact not present")
        clf = ContentClassifier.load(str(model_root), "v0.1.0")
        res = clf.predict("Your account is suspended. Click here to verify your password.")
        assert isinstance(res, ClassificationResult)
        assert res.label in ("phishing", "legitimate")
        assert 0.0 <= res.confidence <= 1.0
        assert res.model_version == "v0.1.0"
