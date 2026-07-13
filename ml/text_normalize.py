"""
Shared email → normalized-text pipeline.

CRITICAL: this exact normalization runs at BOTH training time and inference time.
If the two diverge, the model sees a different distribution in production than it
was trained on. train.py, evaluate.py, diagnose.py and inference.py all import
from here.

Why this exists
---------------
The v0.1.0 model scored F1 0.9985 by learning *corpus artifacts*, not phishing:
  - the honeypot recipient `phishing@pot` (a literal label leak in phishing bodies)
  - RFC822 headers / dates / `00:00:00` timestamps present in one class only
  - modern years (2023-2026) vs Enron-era (2000-2001)
  - HTML/quoted-printable markup in phishing but not in plaintext ham

This module removes those handles so the classifier is forced to learn content:
  1. Parse email → keep ONLY Subject + body (never To/From/Received/Date headers).
  2. Decode transfer-encodings; strip HTML to visible text (applied to every class).
  3. Replace URLs → " url ", emails → " email ", numbers/dates/times → " num ".
  4. Lowercase and collapse whitespace.

The URL/email/number placeholders are kept (not deleted) because "contains a link"
or "contains a number" is legitimate weak signal — we only remove the *identity*
of the specific link/address/date, which is where the leakage lived.
"""
from __future__ import annotations

import email
import html
import re
from email.message import Message
from pathlib import Path

# ── Regexes (compiled once) ───────────────────────────────────────────────────
_STYLE_SCRIPT = re.compile(r"<(style|script)\b[^>]*>.*?</\1>", re.I | re.S)
_TAG = re.compile(r"<[^>]+>")
_URL = re.compile(r"\b(?:https?://|www\.)\S+", re.I)
# Email incl. dotless domains so the honeypot `phishing@pot` is caught too.
_EMAIL = re.compile(r"[\w.+\-]+@[\w.\-]+")
# Any token that is mostly digits / date / time / ip / phone.
_NUM = re.compile(r"\b\d[\d:/.\-]*\d\b|\b\d\b")
_WS = re.compile(r"\s+")

# Tokens that are pure corpus-identity or transfer-encoding leakage, not content.
# They dominated the v0.2.0 feature weights (`enron`/`vince` => "legit",
# `utf` => "phishing") purely because of which dataset each class came from.
# `enron`/`vince` are the Enron company/analyst names; the rest are charset /
# MIME-encoding words that survive HTML stripping in one class more than the other.
_STOP = re.compile(
    r"\b(enron|vince|utf|iso|8859|windows-1252|quoted|printable|charset|"
    r"mime|multipart|boundary|nbsp)\b", re.I)


def strip_html(text: str) -> str:
    """HTML → visible text (no external deps)."""
    text = _STYLE_SCRIPT.sub(" ", text)
    text = _TAG.sub(" ", text)
    return html.unescape(text)


def normalize_text(text: str) -> str:
    """Lowercase, strip HTML, and mask URL/email/number identities."""
    if not text:
        return ""
    text = strip_html(text)
    text = text.lower()
    text = _URL.sub(" url ", text)
    text = _EMAIL.sub(" email ", text)
    text = _NUM.sub(" num ", text)
    text = _STOP.sub(" ", text)
    text = _WS.sub(" ", text)
    return text.strip()


def _body_from_message(msg: Message) -> str:
    """Extract visible body text from a parsed email (text/plain + text/html)."""
    parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype not in ("text/plain", "text/html"):
                continue
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                decoded = payload.decode(part.get_content_charset() or "utf-8",
                                         errors="replace")
                parts.append(strip_html(decoded) if ctype == "text/html" else decoded)
            except Exception:
                pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload is not None:
                decoded = payload.decode(msg.get_content_charset() or "utf-8",
                                         errors="replace")
                if msg.get_content_type() == "text/html":
                    decoded = strip_html(decoded)
                parts.append(decoded)
        except Exception:
            pass
    return " ".join(parts)


def from_eml_bytes(raw: bytes) -> str:
    """Parse raw .eml bytes → normalized Subject+body text. Headers dropped."""
    msg = email.message_from_bytes(raw)
    subject = msg.get("Subject", "") or ""
    return normalize_text(f"{subject} {_body_from_message(msg)}")


def from_eml_file(path: str | Path) -> str:
    try:
        return from_eml_bytes(Path(path).read_bytes())
    except Exception:
        return ""


def from_enron_txt(path: str | Path) -> str:
    """
    Enron ham .txt look like:  'Subject: <s>\\nDate: <d> 00:00:00\\n\\n<body>'
    Keep the subject value + body; drop the 'Date:' line and the 'Subject:'
    label so it is processed symmetrically with parsed .eml (which never carry
    those literal header-label tokens).
    """
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    kept: list[str] = []
    for line in raw.splitlines():
        low = line.lower()
        if low.startswith("date:"):
            continue
        if low.startswith("subject:"):
            kept.append(line.split(":", 1)[1])
            continue
        kept.append(line)
    return normalize_text(" ".join(kept))
