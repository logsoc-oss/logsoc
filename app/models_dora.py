# app/models_dora.py — T88
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, Boolean, Enum, Date, Numeric, SmallInteger, ForeignKey
from app.database import Base
import datetime


class DoraIncident(Base):
    __tablename__ = 'dora_incidents'
    id = Column(BigInteger, primary_key=True, index=True)
    case_id = Column(BigInteger, ForeignKey('cases.id', ondelete='SET NULL'), nullable=True, index=True)
    is_major = Column(Boolean, default=False, index=True)
    classification_date = Column(DateTime)
    crit_clients_affected = Column(Boolean, default=False)
    crit_clients_pct = Column(Numeric(5, 2), default=0)
    crit_clients_count = Column(Integer, default=0)
    crit_transactions_pct = Column(Numeric(5, 2), default=0)
    crit_reputational = Column(Boolean, default=False)
    crit_duration_hours = Column(Numeric(5, 1), default=0)
    crit_cross_border = Column(Boolean, default=False)
    crit_data_loss = Column(Boolean, default=False)
    crit_economic_loss_eur = Column(Numeric(15, 2), default=0)
    thresholds_met = Column(Integer, default=0)
    notification_triggered = Column(Boolean, default=False)
    notif_initial_sent = Column(Boolean, default=False)
    notif_initial_at = Column(DateTime)
    notif_intermediate_sent = Column(Boolean, default=False)
    notif_intermediate_at = Column(DateTime)
    notif_final_sent = Column(Boolean, default=False)
    notif_final_at = Column(DateTime)
    authority = Column(String(50), default='')
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class DoraThirdParty(Base):
    __tablename__ = 'dora_third_parties'
    id = Column(BigInteger, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    service_provided = Column(Text, nullable=False)
    criticality = Column(Enum('critical', 'important', 'standard'), default='standard', index=True)
    contract_date = Column(Date)
    contract_expiry = Column(Date)
    has_security_clauses = Column(Boolean, default=False)
    has_notification_clause = Column(Boolean, default=False)
    has_audit_clause = Column(Boolean, default=False)
    has_exit_strategy = Column(Boolean, default=False)
    exit_strategy_doc = Column(Text)
    risk_score = Column(Integer, default=0)
    last_risk_assessment = Column(Date)
    last_audit_date = Column(Date)
    next_audit_due = Column(Date)
    is_concentration_risk = Column(Boolean, default=False)
    is_eu_critical = Column(Boolean, default=False)
    eu_designation_date = Column(Date)
    country = Column(String(10), default='')
    is_eu_established = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class DoraResilienceTest(Base):
    __tablename__ = 'dora_resilience_tests'
    id = Column(BigInteger, primary_key=True, index=True)
    test_name = Column(String(255), nullable=False)
    test_type = Column(Enum('penetration', 'tlpt', 'continuity', 'tabletop', 'technical'),
                      default='penetration', index=True)
    scheduled_date = Column(Date, nullable=False, index=True)
    completed_date = Column(Date)
    scope_description = Column(Text)
    systems_tested = Column(Text)
    status = Column(Enum('scheduled', 'in_progress', 'completed', 'failed', 'cancelled'),
                   default='scheduled', index=True)
    findings_summary = Column(Text)
    vulnerabilities_found = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    remediation_plan = Column(Text)
    remediation_due_date = Column(Date)
    remediation_completed = Column(Boolean, default=False)
    is_tlpt = Column(Boolean, default=False)
    tlpt_supervisor = Column(String(100), default='')
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class DoraGovernance(Base):
    __tablename__ = 'dora_governance'
    id = Column(BigInteger, primary_key=True, index=True)
    pillar = Column(Enum('risk_management', 'incident_reporting', 'resilience_testing',
                         'third_party_risk', 'info_sharing'), unique=True, nullable=False)
    status = Column(Enum('not_started', 'in_progress', 'implemented', 'verified', 'gap'),
                   default='not_started', index=True)
    maturity_level = Column(SmallInteger, default=0)
    evidence_description = Column(Text)
    gap_description = Column(Text)
    remediation_plan = Column(Text)
    last_reviewed_at = Column(DateTime)
    next_review_due = Column(Date)
    updated_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))