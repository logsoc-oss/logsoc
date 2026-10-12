# app/models_reporting.py — T94
from sqlalchemy import Column, BigInteger, Integer, String, Text, DateTime, Boolean, Enum, Date, ForeignKey
from app.database import Base
import datetime


class ReportTemplate(Base):
    __tablename__ = 'report_templates'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    report_type = Column(Enum('nis2', 'dora', 'rgpd', 'iso27001', 'ai_act', 'incident_monthly',
                             'risk_quarterly', 'audit_annual', 'custom'), default='custom', index=True)
    title_template = Column(String(255), nullable=False)
    description = Column(Text)
    sections = Column(Text, nullable=False)
    default_format = Column(Enum('pdf', 'excel', 'csv', 'json', 'html'), default='pdf')
    default_period_days = Column(Integer, default=30)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class ReportSchedule(Base):
    __tablename__ = 'report_schedules'
    id = Column(BigInteger, primary_key=True, index=True)
    template_id = Column(Integer, ForeignKey('report_templates.id', ondelete='CASCADE'), nullable=False, index=True)
    cron_expr = Column(String(50), default='0 0 1 * *')
    recipients = Column(Text)
    format = Column(Enum('pdf', 'excel', 'csv', 'json', 'html'), default='pdf')
    is_active = Column(Boolean, default=True, index=True)
    last_run_at = Column(DateTime)
    last_run_status = Column(String(50), default='')
    last_report_path = Column(String(255), default='')
    created_by = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class ReportHistory(Base):
    __tablename__ = 'report_history'
    id = Column(BigInteger, primary_key=True, index=True)
    template_id = Column(Integer)
    schedule_id = Column(BigInteger)
    title = Column(String(255), nullable=False)
    report_type = Column(String(50), default='', index=True)
    period_start = Column(Date, nullable=False)
    period_end = Column(Date, nullable=False)
    format = Column(String(10), default='pdf')
    file_path = Column(String(255), default='')
    file_size = Column(Integer, default=0)
    status = Column(Enum('generating', 'completed', 'failed', 'expired'), default='generating', index=True)
    error_message = Column(Text)
    generated_by = Column(Integer, default=0)
    generated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), index=True)


class DashboardConfig(Base):
    __tablename__ = 'dashboard_configs'
    id = Column(Integer, primary_key=True, index=True)
    dashboard_type = Column(Enum('direction', 'rssi', 'analyst', 'audit', 'compliance',
                                'risks', 'ti', 'soar'), unique=True, nullable=False)
    name = Column(String(100), nullable=False)
    config = Column(Text, nullable=False)
    required_role = Column(String(50), default='viewer')
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))