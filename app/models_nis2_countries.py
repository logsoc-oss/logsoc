# app/models_nis2_countries.py — T96
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Enum, Date, BigInteger, Numeric
from app.database import Base
import datetime


class Nis2Country(Base):
    __tablename__ = 'nis2_countries'
    id = Column(Integer, primary_key=True, index=True)
    country_code = Column(String(2), unique=True, nullable=False, index=True)
    country_name = Column(String(100), nullable=False)
    law_name = Column(String(255), default='')
    law_date = Column(Date)
    in_force_date = Column(Date)
    transposition_status = Column(Enum('in_force', 'pending', 'in_progress', 'not_started'),
                                  default='not_started', index=True)
    registration_required = Column(Boolean, default=True)
    registration_deadline_days = Column(Integer, default=30)
    registration_portal = Column(String(255), default='')
    transition_period_months = Column(Integer, default=0)
    transition_ends = Column(Date)
    sanction_ee_max_eur = Column(BigInteger, default=10000000)
    sanction_ee_max_pct = Column(Numeric(5, 2), default=2.00)
    sanction_ei_max_eur = Column(BigInteger, default=7000000)
    sanction_ei_max_pct = Column(Numeric(5, 2), default=1.40)
    national_framework = Column(String(100), default='')
    notes = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class Nis2CountryAuthority(Base):
    __tablename__ = 'nis2_country_authorities'
    id = Column(Integer, primary_key=True, index=True)
    country_code = Column(String(2), nullable=False, index=True)
    authority_name = Column(String(255), nullable=False)
    authority_type = Column(Enum('national', 'csirt', 'sectoral'), default='national', index=True)
    contact_email = Column(String(255), default='')
    contact_phone = Column(String(50), default='')
    website = Column(String(255), default='')
    portal_url = Column(String(255), default='')
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class Nis2CountryRequirement(Base):
    __tablename__ = 'nis2_country_requirements'
    id = Column(Integer, primary_key=True, index=True)
    country_code = Column(String(2), nullable=False, index=True)
    has_extended_scope = Column(Boolean, default=False)
    extended_sectors = Column(Text)
    notification_24h = Column(Boolean, default=True)
    notification_72h = Column(Boolean, default=True)
    notification_1month = Column(Boolean, default=True)
    has_national_framework = Column(Boolean, default=False)
    framework_name = Column(String(100), default='')
    director_responsibility = Column(Boolean, default=False)
    director_training_required = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))