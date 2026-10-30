# app/schemas_nis2.py — T87
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date


class ClassificationUpdate(BaseModel):
    entity_type: Optional[str] = None
    entity_name: Optional[str] = None
    sector: Optional[str] = None
    sub_sector: Optional[str] = None
    employee_count: Optional[int] = None
    annual_revenue_eur: Optional[float] = None
    is_micro: Optional[bool] = None
    anssi_registered: Optional[bool] = None
    anssi_registration_date: Optional[date] = None
    anssi_portal_id: Optional[str] = None


class AssessmentUpdate(BaseModel):
    status: Optional[str] = None
    maturity_level: Optional[int] = None
    evidence_description: Optional[str] = None
    evidence_files: Optional[str] = None
    gap_description: Optional[str] = None
    remediation_plan: Optional[str] = None
    remediation_due_date: Optional[date] = None
    approved_by_direction: Optional[bool] = None
    approved_by_user: Optional[int] = None
    next_review_due: Optional[date] = None
    updated_by: int = 0


class GovernanceCreate(BaseModel):
    policy_name: str
    policy_version: str = "1.0"
    approved_by: str
    approved_role: str = ""
    training_required: bool = True
    training_frequency_months: int = 12
    last_training_date: Optional[date] = None
    last_training_attendees: int = 0


class MeasureResponse(BaseModel):
    id: int
    measure_code: str
    title: str
    description: str
    article_ref: str
    iso27001_mapping: str
    recyf_mapping: str
    nist_csf_mapping: str
    display_order: int
    is_active: bool
    class Config:
        from_attributes = True


class AssessmentResponse(BaseModel):
    id: int
    measure_id: int
    status: str
    maturity_level: int
    evidence_description: Optional[str] = None
    gap_description: Optional[str] = None
    remediation_plan: Optional[str] = None
    remediation_due_date: Optional[date] = None
    approved_by_direction: bool
    last_reviewed_at: Optional[datetime] = None
    next_review_due: Optional[date] = None
    class Config:
        from_attributes = True


class MeasureWithAssessment(MeasureResponse):
    assessment: Optional[AssessmentResponse] = None


class ClassificationResponse(BaseModel):
    id: int
    entity_type: str
    entity_name: str
    sector: str
    sub_sector: Optional[str] = None
    employee_count: int
    annual_revenue_eur: float
    is_micro: bool
    anssi_registered: bool
    anssi_registration_date: Optional[date] = None
    anssi_portal_id: str
    class Config:
        from_attributes = True


class GovernanceResponse(BaseModel):
    id: int
    policy_name: str
    policy_version: str
    approved_by: str
    approved_role: str
    approved_at: Optional[datetime] = None
    training_required: bool
    training_frequency_months: int
    last_training_date: Optional[date] = None
    last_training_attendees: int
    next_training_due: Optional[date] = None
    class Config:
        from_attributes = True