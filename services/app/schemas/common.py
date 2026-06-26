"""Shared API response envelope — PhishSkill convention.

All responses: { success, data, meta? }
All errors:    { success: false, message, code }
"""
from __future__ import annotations

from typing import Any, Generic, Optional, TypeVar
from pydantic import BaseModel

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    success: bool = True
    data: T
    meta: Optional[dict[str, Any]] = None


class ApiError(BaseModel):
    success: bool = False
    message: str
    code: str
