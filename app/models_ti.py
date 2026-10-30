# app/models_ti.py — T93
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, Boolean, Enum, Date, SmallInteger, ForeignKey
from app.database import Base
import datetime


class TiIndicator(Base):
    __tablename__ = 'ti_indicators'
    id = Column(BigInteger, primary_key=True, index=True)
    indicator_type = Column(Enum('ip', 'domain', 'url', 'hash_md5', 'hash_sha256', 'email',
                                'filename', 'mutex', 'registry', 'certificate', 'other'),
                           nullable=False, index=True)
    value = Column(String(512), nullable=False, index=True)
    source = Column(String(100), default='', index=True)
    source_id = Column(String(100), default='')
    confidence = Column(SmallInteger, default=50)
    threat_type = Column(String(100), default='')
    malware_family = Column(String(100), default='')
    ttp_techniques = Column(String(255), default='')
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True, index=True)
    tags = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class TiActor(Base):
    __tablename__ = 'ti_actors'
    id = Column(BigInteger, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    aliases = Column(Text)
    actor_type = Column(Enum('apt', 'cybercriminal', 'hacktivist', 'insider', 'nation_state', 'unknown'),
                       default='unknown', index=True)
    motivation = Column(String(100), default='')
    origin_country = Column(String(10), default='')
    target_countries = Column(Text)
    target_sectors = Column(Text)
    mitre_techniques = Column(Text)
    known_malware = Column(Text)
    description = Column(Text)
    is_active = Column(Boolean, default=True, index=True)
    last_activity = Column(Date)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class TiFeed(Base):
    __tablename__ = 'ti_feeds'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    feed_type = Column(Enum('misp', 'opencti', 'virustotal', 'abuseipdb', 'otx',
                           'csirt_fr', 'commercial', 'custom'), default='custom', index=True)
    base_url = Column(String(255), default='')
    api_key = Column(String(255), default='')
    sync_interval_minutes = Column(Integer, default=60)
    last_sync_at = Column(DateTime)
    last_sync_status = Column(String(50), default='')
    last_sync_count = Column(Integer, default=0)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class TiBulletin(Base):
    __tablename__ = 'ti_bulletins'
    id = Column(BigInteger, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)
    body = Column(Text, nullable=False)
    severity = Column(Enum('info', 'low', 'medium', 'high', 'critical'), default='info', index=True)
    related_indicators = Column(Text)
    related_actors = Column(Text)
    distribution = Column(Enum('internal', 'partners', 'public'), default='internal', index=True)
    status = Column(Enum('draft', 'published', 'archived'), default='draft', index=True)
    published_at = Column(DateTime)
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class TiCorrelation(Base):
    __tablename__ = 'ti_correlations'
    id = Column(BigInteger, primary_key=True, index=True)
    indicator_id = Column(BigInteger, ForeignKey('ti_indicators.id', ondelete='SET NULL'), nullable=True, index=True)
    alert_id = Column(BigInteger, index=True)
    case_id = Column(BigInteger, index=True)
    correlation_type = Column(Enum('alert_match', 'incident_match', 'ioc_enrichment', 'actor_attribution'),
                              default='alert_match', index=True)
    matched_field = Column(String(100), default='')
    matched_value = Column(String(512), default='')
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))