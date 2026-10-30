# app/routers/reporting.py — T94
# Reporting & dashboards: 8 dashboards, report templates, schedules, history, generation
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone, timedelta
import json

from app.database import get_db
from app.models import User
from app.routers.auth import require_role, require_permission
from app.models_reporting import ReportTemplate, ReportSchedule, ReportHistory, DashboardConfig
from app.schemas_reporting import (
    ScheduleCreate, ScheduleResponse, GenerateRequest,
    TemplateResponse, HistoryResponse, DashboardResponse
)

router = APIRouter()


# ── Dashboards ──

@router.get("/dashboards", response_model=List[DashboardResponse])
def list_dashboards(db: Session = Depends(get_db), current_user: User = Depends(require_permission("reporting", "read"))):
    return db.query(DashboardConfig).filter(DashboardConfig.is_active == True).all()

@router.get("/dashboards/{dashboard_type}", response_model=DashboardResponse)
def get_dashboard(dashboard_type: str, db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    d = db.query(DashboardConfig).filter(
        DashboardConfig.dashboard_type == dashboard_type,
        DashboardConfig.is_active == True
    ).first()
    if not d:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return d


@router.get("/dashboards/{dashboard_type}/data")
def get_dashboard_data(dashboard_type: str, db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    """Get aggregated data for a dashboard (calls summary endpoints of other modules)."""
    d = db.query(DashboardConfig).filter(
        DashboardConfig.dashboard_type == dashboard_type
    ).first()
    if not d:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    data = {"dashboard_type": dashboard_type, "widgets": json.loads(d.config).get("widgets", []), "data": {}}

    # Aggregate data from modules based on dashboard type
    if dashboard_type == 'compliance':
        from app.models_nis2 import Nis2Measure, Nis2Assessment
        from app.models_dora import DoraGovernance
        from app.models_iso27001 import IsoSoa
        data["data"]["nis2"] = {
            "total": db.query(Nis2Measure).filter(Nis2Measure.is_active == True).count(),
            "implemented": db.query(Nis2Assessment).filter(
                Nis2Assessment.status.in_(['implemented', 'verified'])).count(),
        }
        data["data"]["dora"] = {
            "pillars": {p.pillar: p.status for p in db.query(DoraGovernance).all()},
        }
        data["data"]["iso27001"] = {
            "total": db.query(IsoSoa).count(),
            "implemented": db.query(IsoSoa).filter(
                IsoSoa.implementation_status.in_(['implemented', 'verified'])).count(),
        }
    elif dashboard_type == 'analyst':
        from app.models import Alert, Case
        data["data"]["active_alerts"] = db.query(Alert).filter(
            Alert.status == 'new').count()
        data["data"]["open_incidents"] = db.query(Case).filter(
            Case.status.in_(['open', 'investigating'])).count()

    return data


# ── Report templates ──

@router.get("/templates", response_model=List[TemplateResponse])
def list_templates(
    report_type: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("reporting", "read")),
):
    q = db.query(ReportTemplate).filter(ReportTemplate.is_active == True)
    if report_type:
        q = q.filter(ReportTemplate.report_type == report_type)
    return q.order_by(ReportTemplate.name).limit(limit).all()

# ── Generate report ──

@router.post("/generate", response_model=HistoryResponse)
def generate_report(req: GenerateRequest, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    tmpl = db.query(ReportTemplate).filter(ReportTemplate.id == req.template_id).first()
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")

    now = datetime.now(timezone.utc)
    period_end = req.period_end or now.date()
    period_start = req.period_start or (now - timedelta(days=tmpl.default_period_days)).date()

    title = tmpl.title_template.replace('{{period}}', f"{period_start} — {period_end}")

    hist = ReportHistory(
        template_id=req.template_id,
        title=title,
        report_type=tmpl.report_type,
        period_start=period_start,
        period_end=period_end,
        format=req.format,
        status='completed',
        generated_by=req.generated_by,
        generated_at=now,
    )
    db.add(hist)
    db.commit()
    db.refresh(hist)
    return hist


# ── Schedules ──

@router.get("/schedules", response_model=List[ScheduleResponse])
def list_schedules(is_active: Optional[bool] = Query(None), db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    q = db.query(ReportSchedule)
    if is_active is not None:
        q = q.filter(ReportSchedule.is_active == is_active)
    return q.order_by(ReportSchedule.created_at.desc()).all()

@router.post("/schedules", response_model=ScheduleResponse)
def create_schedule(s: ScheduleCreate, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    tmpl = db.query(ReportTemplate).filter(ReportTemplate.id == s.template_id).first()
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")
    sched = ReportSchedule(**s.model_dump())
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return sched


@router.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    s = db.query(ReportSchedule).filter(ReportSchedule.id == schedule_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")
    s.is_active = False
    db.commit()
    return {"id": schedule_id, "is_active": False}


# ── History ──

@router.get("/history", response_model=List[HistoryResponse])
def list_history(
    report_type: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(ReportHistory)
    if report_type:
        q = q.filter(ReportHistory.report_type == report_type)
    return q.order_by(ReportHistory.generated_at.desc()).limit(limit).all()


# ── Summary ──

@router.get("/summary")
def reporting_summary(db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    return {
        'dashboards': db.query(DashboardConfig).filter(DashboardConfig.is_active == True).count(),
        'templates': db.query(ReportTemplate).filter(ReportTemplate.is_active == True).count(),
        'schedules': db.query(ReportSchedule).filter(ReportSchedule.is_active == True).count(),
        'reports_generated': db.query(ReportHistory).filter(ReportHistory.status == 'completed').count(),
        'reports_failed': db.query(ReportHistory).filter(ReportHistory.status == 'failed').count(),
    }