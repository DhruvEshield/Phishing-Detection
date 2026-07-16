"""Tests for AttachmentAnalyzer detector."""
from __future__ import annotations
from app.detectors.attachment_analyzer import AttachmentAnalyzer
from app.schemas.email import AttachmentMeta


def make_attachment(filename: str, content_type: str = "application/octet-stream", size: int = 1024) -> AttachmentMeta:
    return AttachmentMeta(filename=filename, content_type=content_type, size_bytes=size)


def test_no_attachments_scores_zero():
    analyzer = AttachmentAnalyzer()
    signal = analyzer.analyse(attachments=[], weight=0.10)
    assert signal.raw_score == 0.0
    assert signal.flags == []


def test_dangerous_extension_detected():
    analyzer = AttachmentAnalyzer()
    signal = analyzer.analyse(
        attachments=[make_attachment("malware.exe")],
        weight=0.10,
    )
    assert signal.raw_score > 0
    assert any("dangerous_extension" in f for f in signal.flags)


def test_double_extension_detected():
    analyzer = AttachmentAnalyzer()
    signal = analyzer.analyse(
        attachments=[make_attachment("invoice.pdf.exe")],
        weight=0.10,
    )
    assert signal.raw_score > 0
    assert any("double_extension" in f for f in signal.flags)


def test_macro_enabled_office_detected():
    analyzer = AttachmentAnalyzer()
    signal = analyzer.analyse(
        attachments=[make_attachment("report.docm", content_type="application/vnd.ms-word.document.macroEnabled.12")],
        weight=0.10,
    )
    assert signal.raw_score > 0
    assert any("macro_enabled_format" in f for f in signal.flags)


def test_archive_attachment_flagged():
    analyzer = AttachmentAnalyzer()
    signal = analyzer.analyse(
        attachments=[make_attachment("files.zip", content_type="application/zip")],
        weight=0.10,
    )
    assert signal.raw_score > 0
    assert any("archive_attachment" in f for f in signal.flags)


def test_content_type_mismatch_detected():
    analyzer = AttachmentAnalyzer()
    signal = analyzer.analyse(
        attachments=[make_attachment("invoice.exe", content_type="application/pdf")],
        weight=0.10,
    )
    assert signal.raw_score > 0
    assert any("content_type_mismatch" in f for f in signal.flags)


def test_clean_attachment_scores_zero():
    analyzer = AttachmentAnalyzer()
    signal = analyzer.analyse(
        attachments=[make_attachment("report.pdf", content_type="application/pdf")],
        weight=0.10,
    )
    assert signal.raw_score == 0.0
    assert signal.flags == []


def test_score_capped_at_100():
    analyzer = AttachmentAnalyzer()
    attachments = [
        make_attachment(f"malware{i}.exe") for i in range(10)
    ]
    signal = analyzer.analyse(attachments=attachments, weight=0.10)
    assert signal.raw_score <= 100.0
