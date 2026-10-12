# app/schemas_dora.py — T88
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date


class DoraIncidentClassify(BaseModel):
    case_id: Optional[int] = None
    crit_clients_affected: bool = False
    crit_clients_pct: float = 0
    crit_clients_count: int = 0
    crit_transactions_pct: float = 0
    crit_reputational: bool = False
    crit_duration_hours: float = 0
    crit_cross_border: bool = False
    crit_data_loss: bool = False
    crit_economic_loss_eur: float = 0
    created_by: int = 0


class DoraThirdPartyCreate(BaseModel):
    name: str
    service_provided: str
    criticality: str = "standard"
    contract_date: Optional[date] = None
    contract_expiry: Optional[date] = None
    has_security_clauses: bool = False
    has_notification_clause: bool = False
    has_audit_clause: bool = False
    has_exit_strategy: bool = False
    exit_strategy_doc: Optional[str] = None
    risk_score: int = 0
    country: str = ""
    is_eu_established: bool = True


class DoraThirdPartyUpdate(BaseModel):
    criticality: Optional[str] = None
    contract_expiry: Optional[date] = None
    has_security_clauses: Optional[bool] = None
    has_notification_clause: Optional[bool] = None
    has_audit_clause: Optional[bool] = None
    has_exit_strategy: Optional[bool] = None
    risk_score: Optional[int] = None
    last_risk_assessment: Optional[date] = None
    next_audit_due: Optional[date] = None
    is_concentration_risk: Optional[bool] = None
    is_eu_critical: Optional[bool] = None


class DoraResilienceTestCreate(BaseModel):
    test_name: str
    test_type: str = "penetration"
    scheduled_date: date
    scope_description: Optional[str] = None
    systems_tested: Optional[str] = None
    is_tlpt: bool = False
    tlpt_supervisor: str = ""
    created_by: int = 0


class DoraResilienceTestUpdate(BaseModel):
    status: Optional[str] = None
    completed_date: Optional[date] = None
    findings_summary: Optional[str] = None
    vulnerabilities_found: Optional[int] = None
    critical_findings: Optional[int] = None
    remediation_plan: Optional[str] = None
    remediation_due_date: Optional[date] = None
    remediation_completed: Optional[bool] = None


class DoraGovernanceUpdate(BaseModel):
    status: Optional[str] = None
    maturity_level: Optional[int] = None
    evidence_description: Optional[str] = None
    gap_description: Optional[str] = None
    remediation_plan: Optional[str] = None
    next_review_due: Optional[date] = None
    updated_by: int = 0


class DoraIncidentResponse(BaseModel):
    id: int
    case_id: Optional[int] = None
    is_major: bool
    thresholds_met: int
    notification_triggered: bool
    notif_initial_sent: bool
    notif_intermediate_sent: bool
    notif_final_sent: bool
    authority: str
    created_at: Optional[datetime] = None
    class Config:
        from_attributes = True


class DoraThirdPartyResponse(BaseModel):
    id: int
    name: str
    service_provided: str
    criticality: str
    contract_date: Optional[date] = None
    contract_expiry: Optional[date] = None
    has_security_clauses: bool
    has_exit_strategy: bool
    risk_score: int
    is_eu_critical: bool
    country: str
    class Config:
        from_attributes = True


class DoraResilienceTestResponse(BaseModel):
    id: int
    test_name: str
    test_type: str
    scheduled_date: date
    completed_date: Optional[date] = None
    status: str
    vulnerabilities_found: int
    critical_findings: int
    is_tlpt: bool
    class Config:
        from_attributes = True


class DoraGovernanceResponse(BaseModel):
    id: int
    pillar: str
    status: str
    maturity_level: int
    evidence_description: Optional[str] = None
    gap_description: Optional[str] = None
    last_reviewed_at: Optional[datetime] = None
    next_review_due: Optional[date] = None
    class Config:
        from_attributes = True