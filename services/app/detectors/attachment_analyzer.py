"""Attachment analysis detector.

Checks email attachments for malicious indicators:
- Dangerous file extensions (.exe, .bat, .ps1, .js, .vbs etc.)
- Double extensions (.pdf.exe, .docx.bat)
- Macro-enabled Office formats (.docm, .xlsm, .pptm)
- Mismatched content-type vs actual extension
- Suspicious archive files (.zip, .rar, .7z)
"""
from __future__ import annotations

import os
import structlog
from typing import TYPE_CHECKING

from app.detectors.base import Signal
from app.schemas.email import AttachmentMeta

log = structlog.get_logger()

# ── Dangerous extensions ───────────────────────────────────────────────────
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".ps1", ".psm1", ".psd1",
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
    ".jar", ".msi", ".reg",
    ".hta", ".cpl", ".dll",
}

# ── Macro-enabled Office formats ───────────────────────────────────────────
MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm",
    ".dotm", ".xltm", ".potm",
}

# ── Archive extensions ─────────────────────────────────────────────────────
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}

# ── Scores ─────────────────────────────────────────────────────────────────
_DANGEROUS_EXT_SCORE = 40
_DOUBLE_EXT_SCORE = 35
_MACRO_SCORE = 25
_ARCHIVE_SCORE = 10
_CONTENT_TYPE_MISMATCH_SCORE = 20

# ── Content-type to expected extension mapping ─────────────────────────────
_CONTENT_TYPE_MAP = {
    "application/pdf": {".pdf"},
    "image/jpeg": {".jpg", ".jpeg"},
    "image/png": {".png"},
    "image/gif": {".gif"},
    "text/plain": {".txt"},
    "application/msword": {".doc"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {".docx"},
    "application/vnd.ms-excel": {".xls"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {".xlsx"},
}


def _get_extension(filename: str) -> str:
    """Get the final extension of a filename, lowercased."""
    return os.path.splitext(filename.lower())[1]


def _has_double_extension(filename: str) -> bool:
    """Check if filename has a dangerous double extension like invoice.pdf.exe"""
    parts = filename.lower().split(".")
    if len(parts) < 3:
        return False
    # Check if the final extension is dangerous and there's another extension before it
    final_ext = "." + parts[-1]
    second_ext = "." + parts[-2]
    return final_ext in DANGEROUS_EXTENSIONS and second_ext in (
        {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}
        | DANGEROUS_EXTENSIONS
    )


def _content_type_mismatch(filename: str, content_type: str) -> bool:
    """Check if declared content-type doesn't match the file extension."""
    ext = _get_extension(filename)
    expected_exts = _CONTENT_TYPE_MAP.get(content_type.split(";")[0].strip().lower())
    if expected_exts is None:
        return False  # unknown content-type, can't judge
    return ext not in expected_exts


class AttachmentAnalyzer:
    """Analyzes email attachments for malicious indicators."""

    def analyse(self, attachments: list[AttachmentMeta], weight: float) -> Signal:
        flags: list[str] = []
        meta: dict = {}
        score = 0.0

        meta["attachment_count"] = len(attachments)

        if not attachments:
            return Signal(
                name="attachment",
                raw_score=0.0,
                weight=weight,
                flags=[],
                metadata=meta,
            )

        attachment_details = []

        for attachment in attachments:
            filename = attachment.filename
            content_type = attachment.content_type
            att_flags: list[str] = []

            ext = _get_extension(filename)

            # Dangerous extension check
            if ext in DANGEROUS_EXTENSIONS:
                att_flags.append(f"dangerous_extension:{ext}({filename})")
                score += _DANGEROUS_EXT_SCORE

            # Double extension check (runs independently — invoice.pdf.exe should flag both)
            if _has_double_extension(filename):
                att_flags.append(f"double_extension:{filename}")
                score += _DOUBLE_EXT_SCORE

            # Macro-enabled Office format check
            if ext in MACRO_EXTENSIONS:
                att_flags.append(f"macro_enabled_format:{ext}({filename})")
                score += _MACRO_SCORE

            # Archive file check
            if ext in ARCHIVE_EXTENSIONS:
                att_flags.append(f"archive_attachment:{ext}({filename})")
                score += _ARCHIVE_SCORE

            # Content-type mismatch check
            if _content_type_mismatch(filename, content_type):
                att_flags.append(
                    f"content_type_mismatch:{filename}(declared:{content_type},ext:{ext})"
                )
                score += _CONTENT_TYPE_MISMATCH_SCORE

            if att_flags:
                attachment_details.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": attachment.size_bytes,
                    "flags": att_flags,
                })
                flags.extend(att_flags)

        meta["suspicious_attachments"] = attachment_details
        raw_score = min(score, 100.0)

        log.info(
            "detector.attachment",
            score=raw_score,
            attachment_count=len(attachments),
            action="attachment_analysis",
        )

        return Signal(
            name="attachment",
            raw_score=raw_score,
            weight=weight,
            flags=flags,
            metadata=meta,
        )
