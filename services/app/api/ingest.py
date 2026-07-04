"""Ingest route — thin controller."""
from __future__ import annotations

from fastapi import APIRouter, Depends, UploadFile, File
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.common import ApiResponse
from app.schemas.email import EmailIngestRequest
from app.schemas.scoring import EmailAnalysisResponse
from app.services.detection_service import DetectionService

router = APIRouter()


@router.post(
    "/emails/ingest",
    response_model=ApiResponse[EmailAnalysisResponse],
    summary="Ingest an email for phishing analysis",
)
async def ingest_email(
    request: EmailIngestRequest,
    db: Session = Depends(get_db),
) -> ApiResponse[EmailAnalysisResponse]:
    svc = DetectionService(db)
    result = await svc.analyse(request)
    return ApiResponse(
        data=result,
        meta={"routing": result.routing_decision, "tier": result.risk_tier},
    )


def _parse_eml(raw: bytes) -> EmailIngestRequest:
    import email as email_lib
    msg = email_lib.message_from_bytes(raw)
    headers = {}
    seen: set = set()
    for key, val in msg.items():
        if key not in seen:
            headers[key] = val
            seen.add(key)
    body_text = ""
    body_html = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not body_text:
                body_text = part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
            elif part.get_content_type() == "text/html" and not body_html:
                body_html = part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
    else:
        body_text = msg.get_payload(decode=True).decode(
            msg.get_content_charset() or "utf-8", errors="replace"
        )
    return EmailIngestRequest(
        headers=headers,
        body_text=body_text,
        body_html=body_html,
        attachments=[],
        raw_mime=None,
        metadata={"source": "eml_upload"},
    )


@router.post(
    "/emails/ingest/eml",
    response_model=ApiResponse[EmailAnalysisResponse],
    summary="Ingest a raw .eml file for phishing analysis",
)
async def ingest_eml_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> ApiResponse[EmailAnalysisResponse]:
    raw = await file.read()
    request = _parse_eml(raw)
    svc = DetectionService(db)
    result = await svc.analyse(request)
    return ApiResponse(
        data=result,
        meta={"routing": result.routing_decision, "tier": result.risk_tier},
    )
