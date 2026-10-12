# app/models_onboarding.py — Ticket #35: Onboarding wizard config
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from app.database import Base
import datetime


class OnboardingConfig(Base):
    __tablename__ = 'onboarding_config'
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    country = Column(String(10), nullable=False)
    sector = Column(String(50), nullable=False)
    company_size = Column(String(20), nullable=False)
    nis2_category = Column(String(50))
    nis2_answer = Column(String(20))  # "yes", "no", "unknown"
    detailed_sector = Column(String(50))
    service_criticality = Column(String(20))
    employee_count = Column(Integer)
    auto_config = Column(JSON)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))