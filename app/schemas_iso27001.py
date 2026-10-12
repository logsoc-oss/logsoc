# app/schemas_iso27001.py — T90
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date


class SoaUpdate(BaseModel):
    is_applicable: Optional[bool] = None
    justification: Optional[str] = None
    implementation_status: Optional[str] = None
    implementation_evidence: Optional[str] = None
    control_owner: Optional[str] = None
    nis2_mapping: Optional[str] = None
    dora_mapping: Optional[str] = None
    rgpd_mapping: Optional[str] = None
    next_review_due: Optional[date] = None


class AuditCreate(BaseModel):
    audit_name: str
    audit_type: str = "internal"
    planned_date: date
    scope: str
    auditor: str
    auditor_org: str = ""
    created_by: int = 0


class AuditUpdate(BaseModel):
    status: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    findings_summary: Optional[str] = None
    nc_count: Optional[int] = None
    nc_major: Optional[int] = None
    nc_minor: Optional[int] = None
    observations: Optional[int] = None
    report_path: Optional[str] = None
    report_date: Optional[date] = None


class NonconformityCreate(BaseModel):
    audit_id: Optional[int] = None
    control_id: Optional[str] = None
    title: str
    description: str
    severity: str = "minor"
    corrective_action: str
    corrective_action_owner: str = ""
    corrective_action_due: Optional[date] = None
    created_by: int = 0


class NonconformityUpdate(BaseModel):
    root_cause_analysis: Optional[str] = None
    corrective_action_completed: Optional[date] = None
    effectiveness_check: Optional[str] = None
    effectiveness_checked: Optional[bool] = None
    effectiveness_verified: Optional[bool] = None
    status: Optional[str] = None


class ManagementReviewCreate(BaseModel):
    review_date: date
    chairperson: str
    participants: Optional[str] = None
    status_previous_actions: Optional[str] = None
    changes_external_internal: Optional[str] = None
    performance_info: Optional[str] = None
    audit_results: Optional[str] = None
    risk_assessment_results: Optional[str] = None
    improvement_opportunities: Optional[str] = None
    decisions: Optional[str] = None
    action_items: Optional[str] = None


class CertificationCreate(BaseModel):
    cert_body: str
    cert_number: str = ""
    initial_cert_date: Optional[date] = None
    surveillance_1_date: Optional[date] = None
    surveillance_2_date: Optional[date] = None
    recertification_date: Optional[date] = None
    expiry_date: Optional[date] = None
    status: str = "in_progress"
    scope: Optional[str] = None


class SoaResponse(BaseModel):
    id: int
    control_id: str
    theme: str
    title: str
    description: str
    is_applicable: bool
    implementation_status: str
    control_owner: str
    class Config:
        from_attributes = True


class AuditResponse(BaseModel):
    id: int
    audit_name: str
    audit_type: str
    planned_date: date
    status: str
    auditor: str
    nc_count: int
    class Config:
        from_attributes = True


class NonconformityResponse(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    control_id: Optional[str] = None
    corrective_action: str
    class Config:
        from_attributes = True


class ManagementReviewResponse(BaseModel):
    id: int
    review_date: date
    chairperson: str
    status: str
    class Config:
        from_attributes = True


class CertificationResponse(BaseModel):
    id: int
    cert_body: str
    cert_number: str
    status: str
    expiry_date: Optional[date] = None
    class Config:
        from_attributes = True