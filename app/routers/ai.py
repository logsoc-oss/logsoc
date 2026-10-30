from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from typing import List, Optional
from app.database import get_db
from app.models import Agent, AIInsight, User
from app.schemas import AIInsightResponse, AIInsightCreate, AIInsightUpdate
from app.routers.auth import require_role
from datetime import datetime
import json

router = APIRouter()


# ── AI Insights ──

@router.get("/insights", response_model=List[AIInsightResponse])
def list_insights(
    insight_type: Optional[str] = None,
    severity: Optional[str] = None,
    dismissed: bool = False,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(AIInsight).filter(AIInsight.is_dismissed == dismissed)
    if insight_type:
        q = q.filter(AIInsight.insight_type == insight_type)
    if severity:
        q = q.filter(AIInsight.severity == severity)
    q = q.order_by(AIInsight.created_at.desc()).limit(limit)
    return q.all()


@router.get("/insights/{insight_id}", response_model=AIInsightResponse)
def get_insight(insight_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user"))):
    insight = db.query(AIInsight).filter(AIInsight.id == insight_id).first()
    if not insight:
        raise HTTPException(status_code=404, detail="Insight not found")
    return insight


@router.post("/insights", response_model=AIInsightResponse)
def create_insight(data: AIInsightCreate, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin"))):
    if data.insight_type not in ('pattern', 'anomaly', 'recommendation', 'threat'):
        raise HTTPException(status_code=400, detail="Invalid insight_type. Must be: pattern, anomaly, recommendation, threat")
    if data.severity not in ('low', 'medium', 'high', 'critical'):
        raise HTTPException(status_code=400, detail="Invalid severity. Must be: low, medium, high, critical")
    insight = AIInsight(
        insight_type=data.insight_type,
        severity=data.severity,
        title=data.title,
        description=data.description,
        evidence=data.evidence,
        affected_hosts=data.affected_hosts,
        recommendation=data.recommendation,
        source=data.source,
        confidence=data.confidence,
        event_count=data.event_count,
    )
    db.add(insight)
    db.commit()
    db.refresh(insight)
    return insight


@router.put("/insights/{insight_id}", response_model=AIInsightResponse)
def update_insight(insight_id: int, data: AIInsightUpdate, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin"))):
    insight = db.query(AIInsight).filter(AIInsight.id == insight_id).first()
    if not insight:
        raise HTTPException(status_code=404, detail="Insight not found")
    if data.is_dismissed is not None:
        insight.is_dismissed = data.is_dismissed
    if data.severity is not None:
        insight.severity = data.severity
    if data.recommendation is not None:
        insight.recommendation = data.recommendation
    db.commit()
    db.refresh(insight)
    return insight


@router.delete("/insights/{insight_id}")
def delete_insight(insight_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin"))):
    insight = db.query(AIInsight).filter(AIInsight.id == insight_id).first()
    if not insight:
        raise HTTPException(status_code=404, detail="Insight not found")
    db.delete(insight)
    db.commit()
    return {"message": "Insight deleted"}


@router.get("/insights/stats/summary")
def insights_stats(db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user"))):
    total = db.query(AIInsight).filter(AIInsight.is_dismissed == False).count()
    by_type = {}
    for row in db.query(AIInsight.insight_type, func.count(AIInsight.id)).filter(AIInsight.is_dismissed == False).group_by(AIInsight.insight_type).all():
        by_type[row[0]] = row[1]
    by_severity = {}
    for row in db.query(AIInsight.severity, func.count(AIInsight.id)).filter(AIInsight.is_dismissed == False).group_by(AIInsight.severity).all():
        by_severity[row[0]] = row[1]
    return {
        "total": total,
        "by_type": by_type,
        "by_severity": by_severity,
    }


# ── Auto-generate insights from event patterns ──
@router.post("/insights/analyze")
def analyze_patterns(db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin"))):
    """Analyze ClickHouse events and agent data to auto-generate AI insights."""
    insights_created = 0

    # Check for agents not seen recently (potential offline agents)
    agents = db.query(Agent).all()
    offline_hosts = [a.hostname for a in agents if a.status in ('pending', 'revoked')]
    if offline_hosts:
        # Check if we already have this insight
        existing = db.query(AIInsight).filter(
            AIInsight.title == "Inactive agents detected",
            AIInsight.is_dismissed == False
        ).first()
        if not existing:
            insight = AIInsight(
                insight_type='anomaly',
                severity='high',
                title='Inactive agents detected',
                description=f'{len(offline_hosts)} agent(s) are not reporting status.',
                affected_hosts=','.join(offline_hosts[:10]),
                recommendation='Verify agents are running and network connectivity is maintained. Check agent logs for errors.',
                source='auto',
                confidence=85,
                event_count=len(offline_hosts),
            )
            db.add(insight)
            insights_created += 1

    # Check eBPF status
    ebpf_disabled = [a.hostname for a in agents if a.ebpf_status == 'disabled']
    if ebpf_disabled:
        existing = db.query(AIInsight).filter(
            AIInsight.title == "eBPF monitoring disabled on agents",
            AIInsight.is_dismissed == False
        ).first()
        if not existing:
            insight = AIInsight(
                insight_type='recommendation',
                severity='medium',
                title='eBPF monitoring disabled on agents',
                description=f'{len(ebpf_disabled)} agent(s) have eBPF monitoring disabled, reducing observability.',
                affected_hosts=','.join(ebpf_disabled[:10]),
                recommendation='Enable eBPF on these agents for kernel-level process and network monitoring.',
                source='auto',
                confidence=90,
                event_count=len(ebpf_disabled),
            )
            db.add(insight)
            insights_created += 1

    # Check for recent high-severity alerts pattern
    try:
        from app.clickhouse_client import get_ch_client
        ch = get_ch_client()
        if ch:
            # Brute force detection: multiple failed SSH from same host
            result = ch.query("""
                SELECT source_host, count() as cnt
                FROM logsoc.siem_logs
                WHERE message LIKE '%Failed password%'
                  AND received_at >= now() - INTERVAL 24 HOUR
                GROUP BY source_host
                ORDER BY cnt DESC
                LIMIT 5
            """)
            if result.result_rows:
                for row in result.result_rows:
                    host, cnt = row[0], row[1]
                    if cnt >= 3:
                        existing = db.query(AIInsight).filter(
                            AIInsight.title.like(f"Brute force SSH attempt detected on {host}"),
                            AIInsight.is_dismissed == False
                        ).first()
                        if not existing:
                            insight = AIInsight(
                                insight_type='threat',
                                severity='critical' if cnt >= 10 else 'high',
                                title=f'Brute force SSH attempt detected on {host}',
                                description=f'{cnt} failed login attempts from {host} in the last 24 hours.',
                                evidence=json.dumps({"host": host, "attempts": cnt}),
                                affected_hosts=host,
                                recommendation='Consider blocking the source IP, enabling fail2ban, or enforcing key-based authentication.',
                                source='auto',
                                confidence=min(95, 60 + cnt),
                                event_count=cnt,
                            )
                            db.add(insight)
                            insights_created += 1

            # Unusual service activity
            result2 = ch.query("""
                SELECT service, count() as cnt
                FROM logsoc.siem_logs
                WHERE severity >= 3
                  AND received_at >= now() - INTERVAL 1 HOUR
                GROUP BY service
                ORDER BY cnt DESC
                LIMIT 5
            """)
            if result2.result_rows:
                for row in result2.result_rows:
                    service, cnt = row[0], row[1]
                    if cnt >= 5:
                        existing = db.query(AIInsight).filter(
                            AIInsight.title.like(f"High severity activity on {service}"),
                            AIInsight.is_dismissed == False
                        ).first()
                        if not existing:
                            insight = AIInsight(
                                insight_type='pattern',
                                severity='medium',
                                title=f'High severity activity on {service}',
                                description=f'{cnt} high-severity events from {service} in the last hour.',
                                evidence=json.dumps({"service": service, "count": cnt}),
                                recommendation=f'Review {service} logs for potential misconfiguration or compromise.',
                                source='auto',
                                confidence=75,
                                event_count=cnt,
                            )
                            db.add(insight)
                            insights_created += 1
    except Exception:
        # ClickHouse not available, skip event-based insights
        pass

    db.commit()
    return {"insights_created": insights_created, "message": f"Generated {insights_created} new insights"}