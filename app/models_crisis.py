# app/models_crisis.py — T86
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, Boolean, Enum, ForeignKey
from app.database import Base
import datetime


class CrisisEvent(Base):
    __tablename__ = 'crisis_events'
    id = Column(BigInteger, primary_key=True, index=True)
    case_id = Column(BigInteger, ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    status = Column(Enum('active', 'contained', 'resolved', 'postmortem', 'closed', 'archived'),
                    default='active', index=True)
    severity = Column(Enum('critical', 'high', 'medium'), default='critical')
    scenario = Column(String(100), default='')
    activated_by = Column(Integer, default=0)
    activated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    contained_at = Column(DateTime)
    resolved_at = Column(DateTime)
    closed_at = Column(DateTime)
    archived_at = Column(DateTime)
    archived_by = Column(Integer)
    crisis_manager = Column(Integer)
    summary = Column(Text)
    description = Column(Text)
    crisis_type = Column(String(64), nullable=False, default='security')
    is_test = Column(Boolean, default=False)
    playbook_id = Column(Integer, nullable=True)
    impact_assessment = Column(Text)
    report_path = Column(String(500))  # path to generated PDF report
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class CrisisCellMember(Base):
    __tablename__ = 'crisis_cell_members'
    id = Column(BigInteger, primary_key=True, index=True)
    crisis_id = Column(BigInteger, ForeignKey('crisis_events.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = Column(Integer)
    name = Column(String(100), nullable=False)
    role = Column(String(100), nullable=False)
    contact = Column(String(255))
    joined_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    left_at = Column(DateTime)
    is_active = Column(Boolean, default=True)


class CrisisAction(Base):
    __tablename__ = 'crisis_actions'
    id = Column(BigInteger, primary_key=True, index=True)
    crisis_id = Column(BigInteger, ForeignKey('crisis_events.id', ondelete='CASCADE'), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    assigned_to = Column(String(100))
    status = Column(Enum('pending', 'in_progress', 'completed', 'cancelled'), default='pending', index=True)
    priority = Column(Enum('critical', 'high', 'medium', 'low'), default='high')
    due_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class CrisisCommunication(Base):
    __tablename__ = 'crisis_communications'
    id = Column(BigInteger, primary_key=True, index=True)
    crisis_id = Column(BigInteger, ForeignKey('crisis_events.id', ondelete='CASCADE'), nullable=False, index=True)
    audience = Column(Enum('internal', 'clients', 'press', 'authorities', 'partners', 'public'), index=True)
    channel = Column(Enum('email', 'phone', 'portal', 'press_release', 'social_media', 'sms'), default='email')
    subject = Column(String(255))
    body = Column(Text)
    sent_by = Column(Integer, default=0)
    sent_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    status = Column(Enum('draft', 'approved', 'sent', 'cancelled'), default='draft')
    approved_by = Column(Integer)
    approved_at = Column(DateTime)


class CrisisPostmortem(Base):
    __tablename__ = 'crisis_postmortem'
    id = Column(BigInteger, primary_key=True, index=True)
    crisis_id = Column(BigInteger, ForeignKey('crisis_events.id', ondelete='CASCADE'), nullable=False, unique=True)
    timeline = Column(Text)
    what_happened = Column(Text, nullable=False)
    why_it_happened = Column(Text)
    what_went_well = Column(Text)
    what_went_wrong = Column(Text)
    lessons_learned = Column(Text)
    corrective_actions = Column(Text)
    preventive_measures = Column(Text)
    written_by = Column(Integer, default=0)
    reviewed_by = Column(Integer)
    reviewed_at = Column(DateTime)
    status = Column(Enum('draft', 'reviewed', 'approved', 'archived'), default='draft')
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class CrisisPlaybook(Base):
    __tablename__ = 'crisis_playbooks'
    id = Column(Integer, primary_key=True, index=True)
    scenario = Column(String(100), unique=True, nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    crisis_type = Column(String(64), nullable=False, default='security')
    severity = Column(String(16), default='high')
    is_template = Column(Boolean, default=False)
    steps = Column(Text, nullable=False)
    communication_plan = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class CrisisPlaybookStep(Base):
    __tablename__ = 'crisis_playbook_steps'
    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, ForeignKey('crisis_playbooks.id', ondelete='CASCADE'), nullable=False, index=True)
    step_number = Column(Integer, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    action = Column(Text)
    responsible_role = Column(String(64), default='admin')
    validation_criteria = Column(Text)
    escalation = Column(Text)


class CrisisSessionStep(Base):
    __tablename__ = 'crisis_session_steps'
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(BigInteger, ForeignKey('crisis_events.id', ondelete='CASCADE'), nullable=False, index=True)
    step_number = Column(Integer, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    action = Column(Text)
    status = Column(String(16), default='pending')
    completed_by = Column(Integer, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)


class CrisisSessionAsset(Base):
    __tablename__ = 'crisis_session_assets'
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(BigInteger, ForeignKey('crisis_events.id', ondelete='CASCADE'), nullable=False, index=True)
    agent_id = Column(Integer, nullable=False)
    impact_level = Column(String(16), default='affected')
    notes = Column(Text, nullable=True)


class CrisisSessionTimelineEntry(Base):
    __tablename__ = 'crisis_session_timeline'
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(BigInteger, ForeignKey('crisis_events.id', ondelete='CASCADE'), nullable=False, index=True)
    event_type = Column(String(32), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


# ── T25: War Room Timeline ──

class CrisisTimelineEntry(Base):
    __tablename__ = 'crisis_timeline'
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, nullable=False, index=True)
    user_id = Column(Integer, nullable=True)
    event_type = Column(Enum('human', 'system', name='timeline_event_type'), default='human', nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    locked = Column(Boolean, default=False)
    locked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


# ── T26: War Room Checklists ──

class CrisisChecklist(Base):
    __tablename__ = 'crisis_checklists'
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, nullable=False, index=True)
    template_type = Column(String(50), nullable=False)
    tasks = Column(Text, nullable=False)  # JSON stored as TEXT for MariaDB compat
    completed_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


# ── T28: Crisis Notifications (IA generation + SMTP send) ──

class CrisisNotification(Base):
    __tablename__ = 'crisis_notifications'
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, nullable=False, index=True)
    authority = Column(String(50), nullable=False)
    regulation = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    status = Column(Enum('draft', 'sent', 'acknowledged'), default='draft', index=True)
    sent_at = Column(DateTime)
    sent_by = Column(Integer)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


# ── T27: War Room — Annuaire + Coffre-fort + Tokens ──

class CrisisContact(Base):
    __tablename__ = 'crisis_contacts'
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, nullable=True)
    # Extended fields (ticket #54): split name into first_name + last_name
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    role = Column(String(100), nullable=True)
    # Extended fields: split phone into phone_pro + phone_astreinte, add mobile
    phone_pro = Column(String(50), nullable=True)
    phone_astreinte = Column(String(50), nullable=True)
    mobile = Column(String(50), nullable=True)
    email = Column(String(100), nullable=True)
    category = Column(Enum('internal', 'legal', 'insurance', 'authority', 'technical',
                            name='crisis_contact_category'), default='internal')
    country = Column(String(10), nullable=True)
    priority = Column(Boolean, default=False)
    available_24_7 = Column(Boolean, default=False)
    notes = Column(Text)
    # Keep name/phone for backward compat (computed from first/last)
    name = Column(String(200), nullable=True)
    phone = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class CrisisVaultDocument(Base):
    __tablename__ = 'crisis_vault_documents'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    type = Column(Enum('network_diagram', 'procedure', 'contact', 'continuity_plan', 'insurance', 'other',
                        name='crisis_vault_doc_type'), default='other')
    encrypted_path = Column(String(500), nullable=False)
    access_level = Column(Enum('crisis_token', 'admin_only',
                                name='crisis_vault_access_level'), default='crisis_token')
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class CrisisToken(Base):
    __tablename__ = 'crisis_tokens'
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, nullable=False, index=True)
    token_hash = Column(String(255), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)