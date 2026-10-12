# app/models_iso27001.py — T90
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, Boolean, Enum, Date, ForeignKey
from app.database import Base
import datetime


class IsoSoa(Base):
    __tablename__ = 'iso_soa'
    id = Column(Integer, primary_key=True, index=True)
    control_id = Column(String(10), unique=True, nullable=False)
    theme = Column(Enum('A.5', 'A.6', 'A.7', 'A.8'), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    is_applicable = Column(Boolean, default=True, index=True)
    justification = Column(Text)
    implementation_status = Column(Enum('not_implemented', 'partial', 'implemented', 'verified', 'not_applicable'),
                                  default='not_implemented', index=True)
    implementation_evidence = Column(Text)
    control_owner = Column(String(100), default='')
    nis2_mapping = Column(String(50), default='')
    dora_mapping = Column(String(50), default='')
    rgpd_mapping = Column(String(50), default='')
    last_reviewed_at = Column(DateTime)
    next_review_due = Column(Date)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class IsoAudit(Base):
    __tablename__ = 'iso_audits'
    id = Column(BigInteger, primary_key=True, index=True)
    audit_name = Column(String(255), nullable=False)
    audit_type = Column(Enum('internal', 'external', 'surveillance', 'recertification', 'pre_assessment'),
                       default='internal', index=True)
    planned_date = Column(Date, nullable=False, index=True)
    start_date = Column(Date)
    end_date = Column(Date)
    scope = Column(Text, nullable=False)
    auditor = Column(String(255), nullable=False)
    auditor_org = Column(String(255), default='')
    status = Column(Enum('planned', 'in_progress', 'completed', 'cancelled', 'failed'),
                   default='planned', index=True)
    findings_summary = Column(Text)
    nc_count = Column(Integer, default=0)
    nc_major = Column(Integer, default=0)
    nc_minor = Column(Integer, default=0)
    observations = Column(Integer, default=0)
    report_path = Column(String(255), default='')
    report_date = Column(Date)
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class IsoNonconformity(Base):
    __tablename__ = 'iso_nonconformities'
    id = Column(BigInteger, primary_key=True, index=True)
    audit_id = Column(BigInteger, ForeignKey('iso_audits.id', ondelete='SET NULL'), nullable=True, index=True)
    control_id = Column(String(10))
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum('major', 'minor', 'observation'), default='minor', index=True)
    root_cause_analysis = Column(Text)
    corrective_action = Column(Text, nullable=False)
    corrective_action_owner = Column(String(100), default='')
    corrective_action_due = Column(Date)
    corrective_action_completed = Column(Date)
    effectiveness_check = Column(Text)
    effectiveness_checked = Column(Boolean, default=False)
    effectiveness_checked_at = Column(Date)
    effectiveness_verified = Column(Boolean, default=False)
    status = Column(Enum('open', 'in_progress', 'corrected', 'verified', 'closed'),
                   default='open', index=True)
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class IsoManagementReview(Base):
    __tablename__ = 'iso_management_reviews'
    id = Column(BigInteger, primary_key=True, index=True)
    review_date = Column(Date, nullable=False, index=True)
    chairperson = Column(String(100), nullable=False)
    participants = Column(Text)
    status_previous_actions = Column(Text)
    changes_external_internal = Column(Text)
    performance_info = Column(Text)
    audit_results = Column(Text)
    risk_assessment_results = Column(Text)
    improvement_opportunities = Column(Text)
    decisions = Column(Text)
    action_items = Column(Text)
    status = Column(Enum('planned', 'completed', 'cancelled'), default='planned', index=True)
    minutes_path = Column(String(255), default='')
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class IsoCertification(Base):
    __tablename__ = 'iso_certification'
    id = Column(Integer, primary_key=True, index=True)
    cert_body = Column(String(255), nullable=False)
    cert_number = Column(String(100), default='')
    initial_cert_date = Column(Date)
    surveillance_1_date = Column(Date)
    surveillance_2_date = Column(Date)
    recertification_date = Column(Date)
    expiry_date = Column(Date)
    status = Column(Enum('certified', 'suspended', 'withdrawn', 'in_progress', 'expired'),
                   default='in_progress')
    scope = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))