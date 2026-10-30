# app/models_regulatory.py — T85
# Models for regulatory notifications (NIS2 / DORA / RGPD / AI Act)
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, Boolean, Enum, ForeignKey
from app.database import Base
import datetime


class RegulatoryNotification(Base):
    __tablename__ = 'regulatory_notifications'
    id = Column(BigInteger, primary_key=True, index=True)
    incident_id = Column(BigInteger, ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    regulation = Column(Enum('nis2', 'dora', 'rgpd', 'ai_act'), nullable=False, index=True)
    authority = Column(String(100), default='')
    step = Column(Enum('early_alert', 'notification', 'intermediate', 'final', 'completed', 'cancelled'),
                  default='early_alert')
    deadline_at = Column(DateTime, nullable=False, index=True)
    sent_at = Column(DateTime)
    subject = Column(String(255))
    body = Column(Text)
    status = Column(Enum('pending', 'draft', 'sent', 'overdue', 'cancelled'), default='pending', index=True)
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))
    parent_notification_id = Column(BigInteger)


class NotificationTemplate(Base):
    __tablename__ = 'notification_templates'
    id = Column(Integer, primary_key=True, index=True)
    regulation = Column(Enum('nis2', 'dora', 'rgpd', 'ai_act'), nullable=False)
    step = Column(Enum('early_alert', 'notification', 'intermediate', 'final'), nullable=False)
    name = Column(String(100), nullable=False)
    subject_template = Column(String(255), nullable=False)
    body_template = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class NotificationTimer(Base):
    __tablename__ = 'notification_timers'
    id = Column(BigInteger, primary_key=True, index=True)
    notification_id = Column(BigInteger, ForeignKey('regulatory_notifications.id', ondelete='CASCADE'),
                             nullable=False, index=True)
    milestone = Column(String(20), nullable=False)
    milestone_at = Column(DateTime, nullable=False, index=True)
    triggered = Column(Boolean, default=False)
    triggered_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))