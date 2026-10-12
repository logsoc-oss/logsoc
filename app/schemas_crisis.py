# app/schemas_crisis.py — T86
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class CrisisActivate(BaseModel):
    case_id: int
    scenario: str = ""
    severity: str = "critical"
    summary: Optional[str] = None
    activated_by: int = 0


# ── Crisis Session (enhanced) ──

class CrisisSessionCreate(BaseModel):
    title: str
    description: Optional[str] = None
    crisis_type: str = "security"
    severity: str = "high"
    playbook_id: Optional[int] = None
    is_test: bool = False
    asset_ids: List[int] = []

class CrisisSessionUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None

class CrisisSessionStepUpdate(BaseModel):
    status: str  # pending, in_progress, completed, skipped
    notes: Optional[str] = None
    completed_by: Optional[int] = None

class CrisisSessionAssetAdd(BaseModel):
    agent_id: int
    impact_level: str = "affected"
    notes: Optional[str] = None

class CrisisTimelineAdd(BaseModel):
    event_type: str  # created, step_started, step_completed, step_skipped, asset_added, note, resolved
    title: str
    description: Optional[str] = None

class CrisisSessionResolve(BaseModel):
    summary: Optional[str] = None


# ── Playbook schemas (enhanced) ──

class PlaybookStepCreate(BaseModel):
    step_number: int
    title: str
    description: Optional[str] = None
    action: Optional[str] = None
    responsible_role: str = "admin"
    validation_criteria: Optional[str] = None
    escalation: Optional[str] = None

class PlaybookStepResponse(BaseModel):
    id: int
    playbook_id: int
    step_number: int
    title: str
    description: Optional[str] = None
    action: Optional[str] = None
    responsible_role: str = "admin"
    validation_criteria: Optional[str] = None
    escalation: Optional[str] = None
    class Config:
        from_attributes = True

class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    crisis_type: str = "security"
    severity: str = "high"
    is_template: bool = False
    steps: List[PlaybookStepCreate] = []

class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    crisis_type: Optional[str] = None
    severity: Optional[str] = None
    is_template: Optional[bool] = None
    is_active: Optional[bool] = None
    steps: Optional[List[PlaybookStepCreate]] = None


class CrisisActionCreate(BaseModel):
    title: str
    description: Optional[str] = None
    assigned_to: Optional[str] = None
    priority: str = "high"
    due_at: Optional[datetime] = None
    created_by: int = 0


class CrisisActionUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    completed_at: Optional[datetime] = None


class CrisisCommunicationCreate(BaseModel):
    audience: str
    channel: str = "email"
    subject: Optional[str] = None
    body: Optional[str] = None
    sent_by: int = 0


class CrisisCommunicationUpdate(BaseModel):
    status: Optional[str] = None
    approved_by: Optional[int] = None


class CrisisCellMemberAdd(BaseModel):
    user_id: Optional[int] = None
    name: str
    role: str
    contact: Optional[str] = None


class CrisisPostmortemCreate(BaseModel):
    timeline: Optional[str] = None
    what_happened: str
    why_it_happened: Optional[str] = None
    what_went_well: Optional[str] = None
    what_went_wrong: Optional[str] = None
    lessons_learned: Optional[str] = None
    corrective_actions: Optional[str] = None
    preventive_measures: Optional[str] = None
    written_by: int = 0


class CrisisResponse(BaseModel):
    id: int
    case_id: int
    status: str
    severity: str
    scenario: str
    activated_by: int
    activated_at: Optional[datetime] = None
    contained_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    archived_at: Optional[datetime] = None
    archived_by: Optional[int] = None
    crisis_manager: Optional[int] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    crisis_type: str = "security"
    is_test: bool = False
    playbook_id: Optional[int] = None
    impact_assessment: Optional[str] = None
    report_path: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CrisisStatusUpdate(BaseModel):
    """Payload for PATCH /crisis/{crisis_id}/status — Kanban drag-and-drop."""
    status: str


class CrisisArchiveRequest(BaseModel):
    """Payload for POST /crisis/{crisis_id}/archive."""
    archived_by: int = 0


class CrisisDetail(CrisisResponse):
    cell_members: List[dict] = []
    actions: List[dict] = []
    communications: List[dict] = []
    postmortem: Optional[dict] = None


class PlaybookResponse(BaseModel):
    id: int
    scenario: str
    name: str
    description: Optional[str] = None
    crisis_type: str = "security"
    severity: str = "high"
    is_template: bool = False
    steps: str
    communication_plan: Optional[str] = None
    is_active: bool
    playbook_steps: List[PlaybookStepResponse] = []

    class Config:
        from_attributes = True


# ── T25: War Room Timeline ──

class TimelineEntryCreate(BaseModel):
    content: str
    event_type: str = "human"


class TimelineEntryResponse(BaseModel):
    id: int
    incident_id: int
    user_id: Optional[int] = None
    event_type: str
    content: str
    timestamp: datetime
    locked: bool
    locked_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── T26: War Room Checklists ──

class ChecklistCreate(BaseModel):
    template_type: str  # e.g. "ransomware", "phishing", etc.


class ChecklistTaskToggle(BaseModel):
    completed: bool


class ChecklistResponse(BaseModel):
    id: int
    incident_id: int
    template_type: str
    tasks: list
    completed_count: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── T27: War Room — Annuaire + Coffre-fort + Tokens ──

class CrisisContactResponse(BaseModel):
    id: int
    organization_id: Optional[int] = None
    first_name: str
    last_name: str
    name: Optional[str] = None  # backward compat: "first_name last_name"
    role: Optional[str] = None
    phone_pro: Optional[str] = None
    phone_astreinte: Optional[str] = None
    mobile: Optional[str] = None
    phone: Optional[str] = None  # backward compat
    email: Optional[str] = None
    category: str
    country: Optional[str] = None
    priority: bool = False
    available_24_7: bool = False
    notes: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CrisisContactCreate(BaseModel):
    first_name: str
    last_name: str
    role: Optional[str] = None
    phone_pro: Optional[str] = None
    phone_astreinte: Optional[str] = None
    mobile: Optional[str] = None
    email: Optional[str] = None
    category: str = "internal"
    country: Optional[str] = None
    priority: bool = False
    available_24_7: bool = False
    notes: Optional[str] = None
    organization_id: Optional[int] = None


class CrisisContactUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: Optional[str] = None
    phone_pro: Optional[str] = None
    phone_astreinte: Optional[str] = None
    mobile: Optional[str] = None
    email: Optional[str] = None
    category: Optional[str] = None
    country: Optional[str] = None
    priority: Optional[bool] = None
    available_24_7: Optional[bool] = None
    notes: Optional[str] = None


class CrisisVaultDocumentResponse(BaseModel):
    id: int
    name: str
    type: str
    encrypted_path: str
    access_level: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CrisisTokenGenerate(BaseModel):
    incident_id: int
    expires_hours: float = Field(default=4, ge=1, le=24)


class CrisisTokenResponse(BaseModel):
    token: str
    token_id: int
    expires_at: datetime

    class Config:
        from_attributes = True


# ── T28: Crisis Notifications (IA generation + SMTP send) ──

class CrisisNotificationGenerate(BaseModel):
    """Request body for POST /incidents/{id}/notifications/generate"""
    authority: str = Field(..., description="Authority code: anssi, cnil, etc.")
    regulation: str = Field(..., description="Regulation code: nis2, rgpd, dora, etc.")


class CrisisNotificationGenerateResponse(BaseModel):
    """Response for generate endpoint."""
    id: int
    incident_id: int
    template_type: str
    pre_filled_content: str
    authority_contact: str
    status: str = "draft"

    class Config:
        from_attributes = True


class CrisisNotificationSendResponse(BaseModel):
    """Response for send endpoint."""
    id: int
    status: str
    sent_at: Optional[datetime] = None
    message_id: Optional[str] = None

    class Config:
        from_attributes = True


class CrisisNotificationResponse(BaseModel):
    """Full notification response for listing."""
    id: int
    incident_id: int
    authority: str
    regulation: str
    content: str
    status: str
    sent_at: Optional[datetime] = None
    sent_by: Optional[int] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CrisisNotificationAcknowledge(BaseModel):
    """Acknowledge a notification (status -> acknowledged)."""
    pass