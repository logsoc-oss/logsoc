# app/schemas_gdpr_ext.py — T89
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date


class TreatmentCreate(BaseModel):
    name: str
    purpose: str
    data_categories: str
    data_subjects: str
    recipients: Optional[str] = None
    legal_basis: str
    legitimate_interest_assessment: Optional[str] = None
    retention_period: str
    security_measures: Optional[str] = None
    has_sensitive_data: bool = False
    sensitive_data_special_category: Optional[str] = None
    created_by: int = 0


class DpiaCreate(BaseModel):
    treatment_name: str
    treatment_id: Optional[int] = None
    description: str
    necessity_proportionality: str
    risk_assessment: str
    measures: str
    initial_risk_level: str = "medium"
    residual_risk_level: str = "medium"
    cnil_consultation_required: bool = False
    created_by: int = 0


class DataRequestCreate(BaseModel):
    requester_name: str
    requester_email: Optional[str] = None
    right_type: str
    request_description: Optional[str] = None
    treatment_concerned: Optional[str] = None


class DataRequestUpdate(BaseModel):
    status: Optional[str] = None
    response_summary: Optional[str] = None
    refusal_reason: Optional[str] = None
    requester_verified: Optional[bool] = None
    extended: Optional[bool] = None
    extension_reason: Optional[str] = None
    handled_by: Optional[int] = None


class SubprocessorCreate(BaseModel):
    name: str
    service_provided: str
    has_dpa: bool = False
    dpa_date: Optional[date] = None
    dpa_expiry: Optional[date] = None
    certifications: Optional[str] = None
    has_subprocessing: bool = False
    subprocessing_authorized: bool = False
    data_categories: Optional[str] = None
    data_location: Optional[str] = None


class TransferCreate(BaseModel):
    treatment_id: Optional[int] = None
    destination_country: str
    mechanism: str
    adequacy_decision_date: Optional[date] = None
    scc_version: Optional[str] = None
    scc_signed_date: Optional[date] = None
    tia_performed: bool = False
    tia_result: Optional[str] = None
    supplementary_measures: Optional[str] = None


class BreachCreate(BaseModel):
    case_id: Optional[int] = None
    breach_type: str
    breach_description: str
    data_categories: Optional[str] = None
    affected_persons: int = 0
    affected_records: int = 0
    risk_level: str = "low"
    risk_assessment: Optional[str] = None
    notif_exempt: bool = False
    exemption_reason: Optional[str] = None
    created_by: int = 0


class BreachUpdate(BaseModel):
    cnil_notified: Optional[bool] = None
    persons_notified: Optional[bool] = None
    persons_notification_method: Optional[str] = None
    remediation_actions: Optional[str] = None
    regulatory_notification_id: Optional[int] = None


class TreatmentResponse(BaseModel):
    id: int
    name: str
    purpose: str
    data_categories: str
    data_subjects: str
    legal_basis: str
    retention_period: str
    has_sensitive_data: bool
    dpo_reviewed: bool
    class Config:
        from_attributes = True


class DpiaResponse(BaseModel):
    id: int
    treatment_name: str
    status: str
    initial_risk_level: str
    residual_risk_level: str
    cnil_consultation_required: bool
    class Config:
        from_attributes = True


class DataRequestResponse(BaseModel):
    id: int
    requester_name: str
    right_type: str
    status: str
    received_at: Optional[datetime] = None
    response_deadline: date
    responded_at: Optional[datetime] = None
    class Config:
        from_attributes = True


class SubprocessorResponse(BaseModel):
    id: int
    name: str
    service_provided: str
    has_dpa: bool
    status: str
    class Config:
        from_attributes = True


class TransferResponse(BaseModel):
    id: int
    destination_country: str
    mechanism: str
    tia_performed: bool
    class Config:
        from_attributes = True


class BreachResponse(BaseModel):
    id: int
    breach_type: str
    risk_level: str
    cnil_notified: bool
    persons_notified: bool
    affected_persons: int
    class Config:
        from_attributes = True