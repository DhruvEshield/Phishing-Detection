"""Verdicts route — thin controller."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.common import ApiResponse
from app.schemas.feedback import VerdictRequest, VerdictResponse
from app.services.verdict_service import VerdictService

router = APIRouter()


@router.post("/verdicts", response_model=ApiResponse[VerdictResponse],
             summary="Record analyst verdict (approve or quarantine)")
def record_verdict(
    req: VerdictRequest,
    db: Session = Depends(get_db),
) -> ApiResponse:
    # Verify email exists
    from app.models.email import Email
    email = db.query(Email).filter(Email.id == req.email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    svc = VerdictService(db)
    result = svc.record(req)
    return ApiResponse(data=result)
