# app/models_mapping.py — T95
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, Boolean, Enum
from app.database import Base
import datetime


class FrameworkControl(Base):
    __tablename__ = 'framework_controls'
    id = Column(Integer, primary_key=True, index=True)
    framework = Column(String(50), nullable=False, index=True)
    control_id = Column(String(20), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(100), default='')
    iso27001_ref = Column(String(20), default='', index=True)
    nis2_ref = Column(String(20), default='', index=True)
    nist_csf_ref = Column(String(20), default='', index=True)
    display_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class FrameworkMapping(Base):
    __tablename__ = 'framework_mapping'
    id = Column(Integer, primary_key=True, index=True)
    source_framework = Column(String(50), nullable=False, index=True)
    source_control_id = Column(String(20), nullable=False)
    target_framework = Column(String(50), nullable=False, index=True)
    target_control_id = Column(String(20), nullable=False)
    match_quality = Column(Enum('exact', 'partial', 'related'), default='related')
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))