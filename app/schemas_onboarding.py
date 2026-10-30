# app/schemas_onboarding.py — Ticket #35: Onboarding wizard schemas
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class OnboardingRequest(BaseModel):
    """POST /api/v1/onboarding request body."""
    country: str  # 2-letter country code (FR, DE, ES, ...)
    sector: str
    company_size: str  # "lt50", "50to250", "250to1000", "gt1000" or "<50", "<250", ">=250"
    nis2_answer: Optional[str] = None  # "yes", "no", "unknown" (new field from FE)
    nis2_known: bool = True
    nis2_category: Optional[str] = None  # "essential", "important", or None if unknown
    # Sub-questionnaire fields (when nis2_answer == "unknown")
    detailed_sector: Optional[str] = None
    service_criticality: Optional[str] = None
    employee_count: Optional[int] = None


class AutoConfig(BaseModel):
    """Auto-generated configuration based on wizard answers."""
    frameworks_enabled: List[str] = []
    authority_target: str = ""
    nis2_profile: str = ""  # "essential", "important", "unknown"


class OnboardingResponse(BaseModel):
    """POST /api/v1/onboarding response."""
    auto_config: AutoConfig
    config_id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class OnboardingConfigResponse(BaseModel):
    """GET /api/v1/onboarding response — existing config for a user."""
    id: int
    user_id: int
    country: str
    sector: str
    company_size: str
    nis2_category: Optional[str] = None
    nis2_answer: Optional[str] = None
    detailed_sector: Optional[str] = None
    service_criticality: Optional[str] = None
    employee_count: Optional[int] = None
    auto_config: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True