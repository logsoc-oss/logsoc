# app/models_gdpr_ext.py — T89
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, Boolean, Enum, Date, ForeignKey
from app.database import Base
import datetime


class GdprTreatment(Base):
    __tablename__ = 'gdpr_treatments'
    id = Column(BigInteger, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    purpose = Column(Text, nullable=False)
    data_categories = Column(Text, nullable=False)
    data_subjects = Column(Text, nullable=False)
    recipients = Column(Text)
    legal_basis = Column(Enum('consent', 'contract', 'legal_obligation', 'vital_interest',
                             'public_task', 'legitimate_interest'), nullable=False)
    legitimate_interest_assessment = Column(Text)
    retention_period = Column(String(100), nullable=False)
    security_measures = Column(Text)
    has_sensitive_data = Column(Boolean, default=False)
    sensitive_data_special_category = Column(Text)
    dpo_reviewed = Column(Boolean, default=False)
    dpo_reviewed_at = Column(DateTime)
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class GdprDpia(Base):
    __tablename__ = 'gdpr_dpia'
    id = Column(BigInteger, primary_key=True, index=True)
    treatment_name = Column(String(255), nullable=False, index=True)
    treatment_id = Column(BigInteger, ForeignKey('gdpr_treatments.id', ondelete='SET NULL'), nullable=True)
    description = Column(Text, nullable=False)
    necessity_proportionality = Column(Text, nullable=False)
    risk_assessment = Column(Text, nullable=False)
    measures = Column(Text, nullable=False)
    initial_risk_level = Column(Enum('low', 'medium', 'high', 'very_high'), default='medium')
    residual_risk_level = Column(Enum('low', 'medium', 'high', 'very_high'), default='medium')
    cnil_consultation_required = Column(Boolean, default=False)
    cnil_consulted = Column(Boolean, default=False)
    cnil_consultation_date = Column(Date)
    status = Column(Enum('draft', 'in_review', 'approved', 'rejected', 'archived'), default='draft', index=True)
    approved_by = Column(Integer)
    approved_at = Column(DateTime)
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class GdprDataRequest(Base):
    __tablename__ = 'gdpr_data_requests'
    id = Column(BigInteger, primary_key=True, index=True)
    requester_name = Column(String(255), nullable=False)
    requester_email = Column(String(255))
    requester_verified = Column(Boolean, default=False)
    verification_method = Column(String(100))
    right_type = Column(Enum('access', 'rectification', 'erasure', 'restriction',
                             'portability', 'objjection', 'automated_decision', 'information'),
                       nullable=False, index=True)
    request_description = Column(Text)
    treatment_concerned = Column(String(255))
    status = Column(Enum('received', 'in_progress', 'responded', 'refused', 'expired'),
                   default='received', index=True)
    received_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    response_deadline = Column(Date, nullable=False, index=True)
    responded_at = Column(DateTime)
    response_summary = Column(Text)
    refusal_reason = Column(Text)
    extended = Column(Boolean, default=False)
    extended_deadline = Column(Date)
    extension_reason = Column(Text)
    handled_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class GdprSubprocessor(Base):
    __tablename__ = 'gdpr_subprocessors'
    id = Column(BigInteger, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    service_provided = Column(Text, nullable=False)
    has_dpa = Column(Boolean, default=False)
    dpa_date = Column(Date)
    dpa_expiry = Column(Date)
    certifications = Column(String(255))
    last_audit_date = Column(Date)
    next_audit_due = Column(Date)
    has_subprocessing = Column(Boolean, default=False)
    subprocessing_authorized = Column(Boolean, default=False)
    data_categories = Column(Text)
    data_location = Column(String(100))
    status = Column(Enum('active', 'terminated', 'suspended'), default='active', index=True)
    terminated_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class GdprTransfer(Base):
    __tablename__ = 'gdpr_transfers'
    id = Column(BigInteger, primary_key=True, index=True)
    treatment_id = Column(BigInteger, ForeignKey('gdpr_treatments.id', ondelete='SET NULL'), nullable=True)
    destination_country = Column(String(10), nullable=False, index=True)
    mechanism = Column(Enum('adequacy', 'scc', 'bcr', 'code_of_conduct', 'certification', 'derogation'),
                      nullable=False, index=True)
    adequacy_decision_date = Column(Date)
    scc_version = Column(String(50))
    scc_signed_date = Column(Date)
    tia_performed = Column(Boolean, default=False)
    tia_date = Column(Date)
    tia_result = Column(Text)
    supplementary_measures = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class GdprBreach(Base):
    __tablename__ = 'gdpr_breaches'
    id = Column(BigInteger, primary_key=True, index=True)
    case_id = Column(BigInteger, ForeignKey('cases.id', ondelete='SET NULL'), nullable=True, index=True)
    breach_type = Column(Enum('confidentiality', 'integrity', 'availability', 'combination'), nullable=False)
    breach_description = Column(Text, nullable=False)
    data_categories = Column(Text)
    affected_persons = Column(Integer, default=0)
    affected_records = Column(Integer, default=0)
    risk_level = Column(Enum('low', 'high'), default='low', index=True)
    risk_assessment = Column(Text)
    cnil_notified = Column(Boolean, default=False, index=True)
    cnil_notification_date = Column(DateTime)
    cnil_notification_deadline = Column(DateTime)
    persons_notified = Column(Boolean, default=False)
    persons_notification_date = Column(DateTime)
    persons_notification_method = Column(String(100))
    notif_exempt = Column(Boolean, default=False)
    exemption_reason = Column(Text)
    regulatory_notification_id = Column(BigInteger)
    remediation_actions = Column(Text)
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))