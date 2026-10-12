# app/schemas_ti.py — T93
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date


class IndicatorCreate(BaseModel):
    indicator_type: str
    value: str
    source: str = ""
    confidence: int = 50
    threat_type: str = ""
    malware_family: str = ""
    ttp_techniques: str = ""
    tags: Optional[str] = None


class LookupRequest(BaseModel):
    value: str
    indicator_type: Optional[str] = None


class ActorCreate(BaseModel):
    name: str
    aliases: Optional[str] = None
    actor_type: str = "unknown"
    motivation: str = ""
    origin_country: str = ""
    target_countries: Optional[str] = None
    target_sectors: Optional[str] = None
    mitre_techniques: Optional[str] = None
    known_malware: Optional[str] = None
    description: Optional[str] = None


class FeedCreate(BaseModel):
    name: str
    feed_type: str = "custom"
    base_url: str = ""
    api_key: str = ""
    sync_interval_minutes: int = 60


class BulletinCreate(BaseModel):
    title: str
    summary: str
    body: str
    severity: str = "info"
    related_indicators: Optional[str] = None
    related_actors: Optional[str] = None
    distribution: str = "internal"
    created_by: int = 0


class IndicatorResponse(BaseModel):
    id: int
    indicator_type: str
    value: str
    source: str
    confidence: int
    threat_type: str
    malware_family: str
    is_active: bool
    class Config:
        from_attributes = True


class ActorResponse(BaseModel):
    id: int
    name: str
    actor_type: str
    motivation: str
    is_active: bool
    class Config:
        from_attributes = True


class FeedResponse(BaseModel):
    id: int
    name: str
    feed_type: str
    base_url: str
    is_active: bool
    last_sync_at: Optional[datetime] = None
    last_sync_status: str
    last_sync_count: int
    class Config:
        from_attributes = True


class BulletinResponse(BaseModel):
    id: int
    title: str
    summary: str
    severity: str
    status: str
    distribution: str
    class Config:
        from_attributes = True


class LookupResponse(BaseModel):
    value: str
    found: bool
    indicators: List[dict] = []
    correlations: List[dict] = []