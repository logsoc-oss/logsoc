# app/models_aiact.py — T91
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, Boolean, Enum, Date, ForeignKey
from app.database import Base
import datetime


class AiSystem(Base):
    __tablename__ = 'ai_systems'
    id = Column(BigInteger, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    provider = Column(String(255), nullable=False)
    provider_contact = Column(String(255), default='')
    version = Column(String(50), default='')
    purpose = Column(Text, nullable=False)
    use_case = Column(Text)
    data_categories = Column(Text)
    has_personal_data = Column(Boolean, default=False)
    has_sensitive_data = Column(Boolean, default=False)
    entity_role = Column(Enum('provider', 'deployer', 'distributor', 'importer'),
                        default='deployer', index=True)
    risk_level = Column(Enum('unacceptable', 'high', 'limited', 'minimal', 'unclassified'),
                      default='unclassified', index=True)
    classification_date = Column(DateTime)
    classified_by = Column(Integer, default=0)
    is_registered_eu = Column(Boolean, default=False)
    registration_date = Column(Date)
    status = Column(Enum('active', 'deprecated', 'retired', 'planned'), default='active', index=True)
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class AiClassification(Base):
    __tablename__ = 'ai_classification'
    id = Column(BigInteger, primary_key=True, index=True)
    ai_system_id = Column(BigInteger, ForeignKey('ai_systems.id', ondelete='CASCADE'), nullable=False, index=True)
    is_safety_component = Column(Boolean, default=False)
    is_in_regulated_product = Column(Boolean, default=False)
    used_critical_infrastructure = Column(Boolean, default=False)
    used_education = Column(Boolean, default=False)
    used_employment = Column(Boolean, default=False)
    used_essential_services = Column(Boolean, default=False)
    used_law_enforcement = Column(Boolean, default=False)
    used_migration = Column(Boolean, default=False)
    used_justice = Column(Boolean, default=False)
    used_democracy = Column(Boolean, default=False)
    uses_subliminal = Column(Boolean, default=False)
    uses_vulnerability_exploitation = Column(Boolean, default=False)
    uses_social_scoring = Column(Boolean, default=False)
    uses_criminal_prediction = Column(Boolean, default=False)
    uses_facial_scraping = Column(Boolean, default=False)
    uses_realtime_biometric = Column(Boolean, default=False)
    uses_emotion_inference = Column(Boolean, default=False)
    uses_biocategorization = Column(Boolean, default=False)
    uses_untargeted_surveillance = Column(Boolean, default=False)
    risk_level = Column(Enum('unacceptable', 'high', 'limited', 'minimal'), default='minimal', index=True)
    rationale = Column(Text)
    interacts_with_humans = Column(Boolean, default=False)
    generates_content = Column(Boolean, default=False)
    uses_emotion_recognition = Column(Boolean, default=False)
    uses_biometric_categorization = Column(Boolean, default=False)
    transparency_required = Column(Boolean, default=False)
    classified_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    classified_by = Column(Integer, default=0)


class AiDeployerObligation(Base):
    __tablename__ = 'ai_deployer_obligations'
    id = Column(BigInteger, primary_key=True, index=True)
    ai_system_id = Column(BigInteger, ForeignKey('ai_systems.id', ondelete='CASCADE'), nullable=False, index=True)
    uses_per_instructions = Column(Boolean, default=False)
    human_oversight_designated = Column(Boolean, default=False)
    oversight_personnel = Column(Text)
    input_data_quality_checked = Column(Boolean, default=False)
    monitoring_active = Column(Boolean, default=False)
    logs_retained = Column(Boolean, default=False)
    logs_retention_months = Column(Integer, default=6)
    workers_informed = Column(Boolean, default=False)
    informed_date = Column(Date)
    dpia_required = Column(Boolean, default=False)
    dpia_completed = Column(Boolean, default=False)
    persons_informed = Column(Boolean, default=False)
    compliance_status = Column(Enum('not_started', 'in_progress', 'compliant', 'non_compliant'),
                             default='not_started', index=True)
    last_reviewed_at = Column(DateTime)
    next_review_due = Column(Date)
    updated_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class AiIncident(Base):
    __tablename__ = 'ai_incidents'
    id = Column(BigInteger, primary_key=True, index=True)
    ai_system_id = Column(BigInteger, ForeignKey('ai_systems.id', ondelete='CASCADE'), nullable=False, index=True)
    case_id = Column(BigInteger, ForeignKey('cases.id', ondelete='SET NULL'), nullable=True)
    incident_description = Column(Text, nullable=False)
    incident_date = Column(DateTime, nullable=False)
    provider_notified = Column(Boolean, default=False)
    provider_notified_at = Column(DateTime)
    authority_notified = Column(Boolean, default=False)
    authority_notified_at = Column(DateTime)
    authority_name = Column(String(255), default='')
    measures_taken = Column(Text)
    system_suspended = Column(Boolean, default=False)
    regulatory_notification_id = Column(BigInteger)
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class AiTransparency(Base):
    __tablename__ = 'ai_transparency'
    id = Column(BigInteger, primary_key=True, index=True)
    ai_system_id = Column(BigInteger, ForeignKey('ai_systems.id', ondelete='CASCADE'), nullable=False, index=True)
    interaction_notice_displayed = Column(Boolean, default=False)
    interaction_notice_text = Column(Text)
    content_marking_active = Column(Boolean, default=False)
    marking_method = Column(String(100), default='')
    emotion_recognition_disclosed = Column(Boolean, default=False)
    biometric_categorization_disclosed = Column(Boolean, default=False)
    high_risk_persons_informed = Column(Boolean, default=False)
    last_verified_at = Column(DateTime)
    verified_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))