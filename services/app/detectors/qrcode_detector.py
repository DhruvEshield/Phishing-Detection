"""QR code detection module.

Extracts images from email body/HTML, decodes QR codes via pyzbar,
feeds decoded URLs back through URLAnalyzer.
"""
from __future__ import annotations

import base64
import io
import re
import structlog
from typing import TYPE_CHECKING

from app.detectors.base import Signal
import httpx
from app.detectors.domain_intel import extract_domain, ssrf_guard

if TYPE_CHECKING:
    from app.detectors.url import URLAnalyzer

log = structlog.get_logger()

_IMG_SRC_PATTERN = re.compile(
    r'<img[^>]+src=["\']?(data:image/[^"\';\s]+;base64,([^"\'>\s]+))["\']?',
    re.IGNORECASE,
)

_IMG_EXTERNAL_PATTERN = re.compile(
    r'<img[^>]+src=["\']?(https?://[^"\';\s>]+)["\']?',
    re.IGNORECASE,
)


def _extract_base64_images(body_html: str) -> list[bytes]:
    """Extract base64-encoded images from HTML img tags."""
    images = []
    for m in _IMG_SRC_PATTERN.finditer(body_html):
        try:
            images.append(base64.b64decode(m.group(2)))
        except Exception:
            pass
    return images


def _extract_external_images(body_html: str, timeout: float = 5.0) -> list[bytes]:
    """Fetch externally linked images from HTML img tags with SSRF guard."""
    images = []
    for m in _IMG_EXTERNAL_PATTERN.finditer(body_html):
        url = m.group(1)
        try:
            domain = extract_domain(url)
            ssrf_guard(domain)
            resp = httpx.get(url, timeout=timeout, follow_redirects=True)
            if resp.status_code == 200:
                images.append(resp.content)
        except Exception:
            pass
        if len(images) >= 5:  # cap external image fetches
            break
    return images


def _decode_qr_from_bytes(image_bytes: bytes) -> list[str]:
    """Decode QR codes from raw image bytes. Returns list of decoded strings."""
    decoded_urls: list[str] = []
    try:
        from PIL import Image
        from pyzbar import pyzbar
        img = Image.open(io.BytesIO(image_bytes))
        results = pyzbar.decode(img)
        for r in results:
            decoded_urls.append(r.data.decode("utf-8", errors="replace"))
    except ImportError:
        log.warning("qrcode.pyzbar_unavailable")
    except Exception as exc:
        log.warning("qrcode.decode_error", error=str(exc))
    return decoded_urls


class QRCodeDetector:
    def __init__(self, url_analyzer: "URLAnalyzer"):
        self._url_analyzer = url_analyzer

    def analyse(self, body_html: str, weight: float) -> Signal:
        flags: list[str] = []
        meta: dict = {}
        score = 0.0

        images = _extract_base64_images(body_html)[:10]  # cap at 10 to prevent DoS
        # Also fetch externally linked images (capped at 5)
        images += _extract_external_images(body_html)
        meta["images_found"] = len(images)

        decoded_all: list[str] = []
        for img_bytes in images:
            decoded_all.extend(_decode_qr_from_bytes(img_bytes))

        meta["qr_codes_found"] = len(decoded_all)
        meta["decoded_urls"] = decoded_all[:10]

        if decoded_all:
            flags.append(f"qr_codes_found({len(decoded_all)})")
            # Base score just for finding QR codes — suspicious in business emails
            score += 10.0
            # Feed decoded URLs into the URL analyzer
            synthetic_body = " ".join(decoded_all)
            url_signal = self._url_analyzer.analyse(
                body_text=synthetic_body, body_html="", weight=1.0,
            )
            # Scale URL signal into QR score
            score += url_signal.raw_score
            flags.extend([f"qr>{f}" for f in url_signal.flags])
            meta["url_analysis"] = url_signal.metadata

        raw_score = min(score, 100.0)
        log.info("detector.qrcode", score=raw_score, qr_count=len(decoded_all),
                 action="qrcode_analysis")
        return Signal(name="qrcode", raw_score=raw_score, weight=weight,
                      flags=flags, metadata=meta)
