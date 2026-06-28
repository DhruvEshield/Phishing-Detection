"""Ingest route — thin controller."""
from __future__ import annotations

from fastapi import APIRouter, Depends
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
