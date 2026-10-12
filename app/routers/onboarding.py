# app/routers/onboarding.py — Ticket #35: Onboarding wizard endpoints
# Ticket #57: Fix field mismatch + EU countries + NIS2 verification link
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import Optional

from app.database import get_db
from app.models import User
from app.models_onboarding import OnboardingConfig
from app.routers.auth import require_role
from app.schemas_onboarding import (
    OnboardingRequest,
    OnboardingResponse,
    OnboardingConfigResponse,
    AutoConfig,
)
from app.services.onboarding_service import generate_auto_config

router = APIRouter()

# Map FE size values to BE canonical sizes
SIZE_MAP = {
    "lt50": "<50",
    "50to250": "<250",
    "250to1000": ">=250",
    "gt1000": ">=250",
    "<50": "<50",
    "<250": "<250",
    ">=250": ">=250",
}


@router.post("", response_model=OnboardingResponse)
def submit_onboarding(
    payload: OnboardingRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """POST /api/v1/onboarding

    Submit onboarding wizard answers and receive auto-config.
    Auth: admin/superadmin only.
    """
    # Validate required fields
    if not payload.country:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_required_field: country"
        )
    if not payload.sector:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_required_field: sector"
        )
    if not payload.company_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_required_field: company_size"
        )

    # Determine nis2_known from nis2_answer if nis2_answer is provided
    nis2_known = payload.nis2_known
    if payload.nis2_answer:
        nis2_known = payload.nis2_answer == "yes"

    # Determine nis2_category from sub-questionnaire if unknown
    nis2_category = payload.nis2_category
    if payload.nis2_answer == "unknown" and not nis2_category:
        # Auto-determine from sub-questionnaire
        if payload.service_criticality == "high":
            nis2_category = "essential"
        else:
            nis2_category = "important"

    # Normalize company_size to canonical format
    canonical_size = SIZE_MAP.get(payload.company_size, payload.company_size)

    # Generate auto-config from wizard answers
    auto_config_dict = generate_auto_config(
        country=payload.country,
        sector=payload.sector,
        company_size=canonical_size,
        nis2_known=nis2_known,
        nis2_category=nis2_category,
    )

    # Check if config already exists for this user — update or create
    existing = db.query(OnboardingConfig).filter(
        OnboardingConfig.user_id == current_user.id
    ).first()

    if existing:
        existing.country = payload.country
        existing.sector = payload.sector
        existing.company_size = payload.company_size
        existing.nis2_category = nis2_category
        existing.nis2_answer = payload.nis2_answer
        existing.detailed_sector = payload.detailed_sector
        existing.service_criticality = payload.service_criticality
        existing.employee_count = payload.employee_count
        existing.auto_config = auto_config_dict
        existing.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(existing)
        config = existing
    else:
        config = OnboardingConfig(
            user_id=current_user.id,
            country=payload.country,
            sector=payload.sector,
            company_size=payload.company_size,
            nis2_category=nis2_category,
            nis2_answer=payload.nis2_answer,
            detailed_sector=payload.detailed_sector,
            service_criticality=payload.service_criticality,
            employee_count=payload.employee_count,
            auto_config=auto_config_dict,
        )
        db.add(config)
        db.commit()
        db.refresh(config)

    return OnboardingResponse(
        auto_config=AutoConfig(**auto_config_dict),
        config_id=config.id,
        created_at=config.created_at,
        updated_at=config.updated_at,
    )


@router.get("", response_model=Optional[OnboardingConfigResponse])
def get_onboarding(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """GET /api/v1/onboarding

    Return existing onboarding config for the current user, or null if none.
    """
    config = db.query(OnboardingConfig).filter(
        OnboardingConfig.user_id == current_user.id
    ).first()
    if not config:
        return None
    return config