# app/schemas_reporting.py — T94
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date


class ScheduleCreate(BaseModel):
    template_id: int
    cron_expr: str = "0 0 1 * *"
    recipients: Optional[str] = None
    format: str = "pdf"
    created_by: int = 0


class GenerateRequest(BaseModel):
    template_id: int
    period_start: Optional[date] = None
    period_end: Optional[date] = None
    format: str = "pdf"
    generated_by: int = 0


class TemplateResponse(BaseModel):
    id: int
    name: str
    report_type: str
    title_template: str
    default_format: str
    default_period_days: int
    is_active: bool
    class Config:
        from_attributes = True


class ScheduleResponse(BaseModel):
    id: int
    template_id: int
    cron_expr: str
    format: str
    is_active: bool
    last_run_at: Optional[datetime] = None
    last_run_status: str
    class Config:
        from_attributes = True


class HistoryResponse(BaseModel):
    id: int
    title: str
    report_type: str
    period_start: date
    period_end: date
    format: str
    status: str
    file_path: str
    generated_at: datetime
    class Config:
        from_attributes = True


class DashboardResponse(BaseModel):
    id: int
    dashboard_type: str
    name: str
    config: str
    required_role: str
    is_active: bool
    class Config:
        from_attributes = True