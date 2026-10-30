# app/models_frameworks_modular.py — T97
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, Boolean, Enum, Date, SmallInteger
from app.database import Base
import datetime


class FrameworkAssessment(Base):
    __tablename__ = 'framework_assessments'
    id = Column(BigInteger, primary_key=True, index=True)
    framework = Column(String(50), nullable=False, index=True)
    control_id = Column(String(20), nullable=False)
    status = Column(Enum('not_started', 'in_progress', 'implemented', 'verified', 'gap'),
                   default='not_started', index=True)
    maturity_level = Column(SmallInteger, default=0)
    evidence_description = Column(Text)
    gap_description = Column(Text)
    remediation_plan = Column(Text)
    remediation_due_date = Column(Date)
    target_level = Column(String(20), default='')
    current_level = Column(String(20), default='')
    last_reviewed_at = Column(DateTime)
    next_review_due = Column(Date)
    updated_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))