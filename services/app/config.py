"""Application configuration — all settings from env vars, never hard-coded."""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="../.env",
        case_sensitive=False,
        extra="ignore",
        protected_namespaces=(),  # allow model_version / model_path field names
    )

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = "postgresql://phishdetect:phishdetect@localhost:5432/phishdetect"

    # ── Queue ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Scoring thresholds (0–100 scale; config-driven, not hard-coded) ───────
    high_threshold: float = 70.0
    medium_threshold: float = 35.0

    # ── Signal weights  ───────────────────────────────────────────────────────
    # INVARIANT: max(weight_*) * 100 < high_threshold
    # With defaults: 0.30 * 100 = 30 < 70  ✓
    # ScoringConfig validates this on startup.
    weight_header: float = 0.25
    weight_content: float = 0.30
    weight_url: float = 0.25
    weight_qrcode: float = 0.10
    weight_threat_intel: float = 0.10

    # ── ML ────────────────────────────────────────────────────────────────────
    model_version: str = "v0.1.0"
    model_path: str = "ml/models"

    # ── Multi-tenancy (Phase 1: single tenant — nullable) ─────────────────────
    default_tenant_id: Optional[str] = None

    # ── External probes ───────────────────────────────────────────────────────
    rdap_timeout: float = 5.0
    http_probe_timeout: float = 8.0
    max_redirect_hops: int = 5

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: str = "INFO"
    log_format: str = "json"

    # ── Security ──────────────────────────────────────────────────────────────
    secret_key: str = "change-me-in-production"

    # ── External APIs ─────────────────────────────────────────────────────────
    google_safe_browsing_key: Optional[str] = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
