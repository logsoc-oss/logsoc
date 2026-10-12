# app/models_soar.py — T92
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, Boolean, Enum, ForeignKey
from app.database import Base
import datetime


class SoarPlaybook(Base):
    __tablename__ = 'soar_playbooks'
    id = Column(BigInteger, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    trigger_type = Column(Enum('alert_created', 'incident_created', 'ioc_detected',
                              'vuln_critical', 'manual', 'scheduled'), default='manual', index=True)
    trigger_conditions = Column(Text)
    steps = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    version = Column(Integer, default=1)
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class SoarExecution(Base):
    __tablename__ = 'soar_executions'
    id = Column(BigInteger, primary_key=True, index=True)
    playbook_id = Column(BigInteger, ForeignKey('soar_playbooks.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    trigger_type = Column(String(50), default='', index=True)
    trigger_entity_id = Column(BigInteger)
    trigger_entity_type = Column(String(50), default='')
    status = Column(Enum('pending', 'running', 'awaiting_approval', 'completed',
                        'failed', 'cancelled', 'timeout'), default='pending', index=True)
    current_step = Column(Integer, default=0)
    result_summary = Column(Text)
    steps_executed = Column(Text)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_ms = Column(BigInteger, default=0)
    error_message = Column(Text)
    triggered_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class SoarApprovalStep(Base):
    __tablename__ = 'soar_approval_steps'
    id = Column(BigInteger, primary_key=True, index=True)
    execution_id = Column(BigInteger, ForeignKey('soar_executions.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    step_number = Column(Integer, nullable=False)
    approver_role = Column(String(100), default='')
    approver_user_id = Column(Integer)
    status = Column(Enum('pending', 'approved', 'rejected', 'expired'), default='pending', index=True)
    decision = Column(Text)
    approved_at = Column(DateTime)
    timeout_minutes = Column(Integer, default=60)
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class SoarIntegration(Base):
    __tablename__ = 'soar_integrations'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    integration_type = Column(Enum('siem', 'edr', 'firewall', 'itsm', 'email', 'ti',
                                  'webhook', 'custom'), default='custom', index=True)
    base_url = Column(String(255), default='')
    api_key = Column(String(255), default='')
    auth_type = Column(Enum('bearer', 'basic', 'api_key', 'none'), default='bearer')
    supported_actions = Column(Text)
    is_active = Column(Boolean, default=True, index=True)
    last_tested_at = Column(DateTime)
    last_test_result = Column(String(50), default='')
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))