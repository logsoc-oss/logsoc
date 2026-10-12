# app/schemas_regulatory.py — T85
# Pydantic schemas for regulatory notifications
from enum import Enum as PyEnum
import enum
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum


class RegulationEnum(str, enum.Enum):
    nis2 = "nis2"
    dora = "dora"
    rgpd = "rgpd"
    ai_act = "ai_act"


class NotificationTrigger(BaseModel):
    incident_id: int
    regulations: List[RegulationEnum] = Field(default=[RegulationEnum.nis2, RegulationEnum.dora,
                                                        RegulationEnum.rgpd, RegulationEnum.ai_act])
    detected_at: Optional[datetime] = None
    created_by: int = 0


class NotificationCreate(BaseModel):
    incident_id: int
    regulation: RegulationEnum
    step: str = "early_alert"
    authority: str = ""
    deadline_at: datetime
    subject: Optional[str] = None
    body: Optional[str] = None
    created_by: int = 0


class NotificationUpdate(BaseModel):
    subject: Optional[str] = None
    body: Optional[str] = None
    status: Optional[str] = None
    step: Optional[str] = None


class NotificationResponse(BaseModel):
    id: int
    incident_id: int
    regulation: str
    authority: str
    step: str
    deadline_at: datetime
    sent_at: Optional[datetime] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    status: str
    created_by: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    parent_notification_id: Optional[int] = None

    class Config:
        from_attributes = True


class TimerResponse(BaseModel):
    id: int
    notification_id: int
    milestone: str
    milestone_at: datetime
    triggered: bool
    triggered_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class NotificationDetail(NotificationResponse):
    timers: List[TimerResponse] = []


class TemplateResponse(BaseModel):
    id: int
    regulation: str
    step: str
    name: str
    subject_template: str
    body_template: str
    is_active: bool

    class Config:
        from_attributes = True


class NotificationListResponse(BaseModel):
    triggered: int
    notifications: List[dict]