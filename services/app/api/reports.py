"""Inbound reports route — accepts reported emails (PhishSkill integration shape).

Inbound shape: { sender, senderIp, subject, headers, rawEml }
Deduplicates by MD5 of payload (per phishskill-integration.md §2).
Funnels into the same detection pipeline as regular ingest.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.common import ApiResponse
from app.schemas.email import EmailIngestRequest
from app.services.detection_service import DetectionService

router = APIRouter()


class InboundReport(BaseModel):
    """PhishSkill-compatible inbound report shape."""
    sender: str
    sender_ip: Optional[str] = None
    subject: str
    headers: dict[str, str]
    raw_eml: Optional[str] = None
    body_text: str = ""
    tenant_id: Optional[str] = None


@router.post("/reports", response_model=ApiResponse[dict],
             summary="Accept an inbound reported email (PhishSkill report shape)")
async def report_email(
    report: InboundReport,
    db: Session = Depends(get_db),
) -> ApiResponse:
    # Map to standard ingest request
    ingest_req = EmailIngestRequest(
        headers={**report.headers, "From": report.sender, "Subject": report.subject},
        body_text=report.body_text,
        body_html="",
        raw_mime=report.raw_eml,
        sender_ip=report.sender_ip,
        tenant_id=report.tenant_id,
        metadata={"source": "inbound_report"},
    )

    svc = DetectionService(db)
    result = await svc.analyse(ingest_req)
    return ApiResponse(
        data={"email_id": result.email_id, "risk_score": result.risk_score,
              "verdict": result.verdict, "routing": result.routing_decision},
        meta={"source": "inbound_report"},
    )
