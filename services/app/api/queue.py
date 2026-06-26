"""Queue routes — thin controller."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.common import ApiResponse
from app.services.queue_service import QueueService

router = APIRouter()


@router.get("/queue", response_model=ApiResponse[list[dict]],
            summary="List medium-risk emails awaiting analyst review")
def list_queue(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    tenant_id: str | None = Query(None),
    db: Session = Depends(get_db),
) -> ApiResponse:
    svc = QueueService(db)
    items, total = svc.list_pending(page=page, page_size=page_size, tenant_id=tenant_id)
    return ApiResponse(
        data=items,
        meta={"total": total, "page": page, "page_size": page_size},
    )


@router.get("/queue/{email_id}", response_model=ApiResponse[dict],
            summary="Full detail for one queued email")
def get_queue_detail(
    email_id: str,
    db: Session = Depends(get_db),
) -> ApiResponse:
    svc = QueueService(db)
    detail = svc.get_detail(email_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Email not found")
    return ApiResponse(data=detail)
