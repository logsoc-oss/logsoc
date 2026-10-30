# app/models_nis2.py — T87
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, Boolean, Enum, Date, Numeric, SmallInteger, ForeignKey
from app.database import Base
import datetime


class Nis2Classification(Base):
    __tablename__ = 'nis2_classification'
    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(Enum('essential', 'important'), default='important')
    entity_name = Column(String(255), default='')
    sector = Column(String(100), default='')
    sub_sector = Column(String(100))
    employee_count = Column(Integer, default=0)
    annual_revenue_eur = Column(Numeric(15, 2), default=0)
    is_micro = Column(Boolean, default=False)
    self_assessed_at = Column(DateTime)
    self_assessed_by = Column(Integer, default=0)
    anssi_registered = Column(Boolean, default=False)
    anssi_registration_date = Column(Date)
    anssi_portal_id = Column(String(100), default='')
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class Nis2Measure(Base):
    __tablename__ = 'nis2_measures'
    id = Column(Integer, primary_key=True, index=True)
    measure_code = Column(String(10), unique=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    article_ref = Column(String(50), default='Art. 21 §2')
    iso27001_mapping = Column(String(100), default='')
    recyf_mapping = Column(String(100), default='')
    nist_csf_mapping = Column(String(100), default='')
    display_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class Nis2Assessment(Base):
    __tablename__ = 'nis2_assessment'
    id = Column(BigInteger, primary_key=True, index=True)
    measure_id = Column(Integer, ForeignKey('nis2_measures.id', ondelete='CASCADE'), nullable=False, index=True)
    status = Column(Enum('not_started', 'in_progress', 'implemented', 'verified', 'gap'),
                    default='not_started', index=True)
    maturity_level = Column(SmallInteger, default=0)
    evidence_description = Column(Text)
    evidence_files = Column(Text)
    gap_description = Column(Text)
    remediation_plan = Column(Text)
    remediation_due_date = Column(Date)
    approved_by_direction = Column(Boolean, default=False)
    approved_at = Column(DateTime)
    approved_by_user = Column(Integer)
    last_reviewed_at = Column(DateTime)
    last_reviewed_by = Column(Integer)
    next_review_due = Column(Date)
    updated_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class Nis2Governance(Base):
    __tablename__ = 'nis2_governance'
    id = Column(BigInteger, primary_key=True, index=True)
    policy_name = Column(String(255), nullable=False, index=True)
    policy_version = Column(String(20), default='1.0')
    approved_by = Column(String(100), nullable=False)
    approved_role = Column(String(100), default='')
    approved_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    training_required = Column(Boolean, default=True)
    training_frequency_months = Column(Integer, default=12)
    last_training_date = Column(Date)
    last_training_attendees = Column(Integer, default=0)
    next_training_due = Column(Date)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))