"""app/routers/compliance_infra.py — Compliance Infra scoring (C2 RSSI V3, v0.11.2).

2026-06-09. Calcule un score 0-100 par section (PRA/PCA/PRI/SC/Forensics/Tests)
basé sur 3 axes :
  - couverture  (60%) : % de sous-thèmes couverts par au moins 1 procédure
  - fraîcheur   (30%) : % de procédures non en retard de revue
  - risques     (10%) : % de risques fermés (1 - open/total)

Le score est calculé en temps réel (~50ms sur 6 sections × ~10 procédures
× ~6 risques). Optionnellement, POST /snapshot persiste un horodatage
dans compliance_section_scores pour l'historique/audit.
"""
from __future__ import annotations

import datetime
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    RunbookProcedure, RunbookReview, Risk, User, ComplianceSectionScore,
)
from app.routers.auth import get_current_user
from app.routers.compliance_infra_reference import (
    SECTIONS, all_section_keys, all_subthemes_for_section, section_label,
    total_subthemes, covered_subthemes_for_section,
)
from app.schemas import (
    SectionScore, ComplianceStatsResponse, ComplianceScoreSnapshot,
)
from pydantic import BaseModel

logger = logging.getLogger("logsoc.compliance_infra")
router = APIRouter()


# ── Scoring (pure function, easy to test in isolation) ──

W_COVERAGE = 0.60
W_FRESHNESS = 0.30
W_RISKS = 0.10


def compute_section_score(
    section: str,
    procedure_slugs: List[str],
    procedures_overdue_count: int,
    risk_open: int,
    risk_total: int,
) -> SectionScore:
    """Calcule le score d'une section. Pure function (no DB).

    Args:
        section: clé (pra, pca, pri, sc, fore, test).
        procedure_slugs: slugs des procédures de cette section.
        procedures_overdue_count: nombre de procédures en retard (next_review_at < today).
        risk_open: nombre de risques EBIOS avec status != 'closed' pour cette section.
        risk_total: nombre total de risques EBIOS pour cette section.

    Returns:
        SectionScore avec global_score, composantes, et détail sous-thèmes.
    """
    if section not in SECTIONS:
        raise ValueError(f"Unknown section: {section}")

    label = section_label(section)
    all_sub = all_subthemes_for_section(section)
    sub_total = len(all_sub)
    covered = covered_subthemes_for_section(section, procedure_slugs)
    sub_covered = len(covered)
    coverage_pct = (sub_covered / sub_total * 100.0) if sub_total else 0.0

    proc_count = len(procedure_slugs)
    overdue = procedures_overdue_count
    # Freshness = % of procedures not overdue
    if proc_count == 0:
        freshness_pct = 0.0
    else:
        freshness_pct = max(0.0, (1.0 - overdue / proc_count) * 100.0)

    if risk_total == 0:
        risks_closed_pct = 100.0  # No risks = "fully closed" (no exposure)
    else:
        risks_closed_pct = max(0.0, (1.0 - risk_open / risk_total) * 100.0)

    global_score = (
        coverage_pct * W_COVERAGE
        + freshness_pct * W_FRESHNESS
        + risks_closed_pct * W_RISKS
    )
    # Round to 2 decimals
    return SectionScore(
        section=section,
        label=label,
        global_score=round(global_score, 2),
        coverage_pct=round(coverage_pct, 2),
        freshness_pct=round(freshness_pct, 2),
        risks_closed_pct=round(risks_closed_pct, 2),
        procedure_count=proc_count,
        subtheme_count=sub_covered,
        subtheme_total=sub_total,
        subthemes_covered=sorted(covered),
        subthemes_missing=sorted(set(all_sub) - covered),
        risk_open=risk_open,
        risk_total=risk_total,
        procedure_slugs=sorted(procedure_slugs),
    )


# ── DB-backed helpers ──

def _gather_section_inputs(db: Session, section: str) -> tuple[List[str], int, int, int]:
    """Collecte (slugs, overdue_count, risk_open, risk_total) pour une section.

    v0.11.3 (R9) — Risks are now mapped to a section via the
    `compliance_section` column. We filter on that column to compute
    per-section risk counts. Risks with compliance_section=NULL are
    not counted for any section (transverse / gouvernance).

    NOTE: 'open' means any status that is not 'closed' or 'mitigated'
    (consistent with the EBIOS lifecycle: 'mitigated' = risk treated,
    'closed' = accepted/avoided/transfered as final outcome).
    """
    procs = (
        db.query(RunbookProcedure)
        .filter(RunbookProcedure.section == section)
        .all()
    )
    slugs = [p.slug for p in procs]
    today = datetime.date.today()
    overdue = sum(1 for p in procs if p.next_review_at and p.next_review_at < today)

    # v0.11.3 (R9) — Per-section risk counts via compliance_section column
    risk_total = db.query(func.count(Risk.id)).filter(
        Risk.compliance_section == section
    ).scalar() or 0
    risk_open = db.query(func.count(Risk.id)).filter(
        Risk.compliance_section == section,
        Risk.status.in_(['draft', 'assessed', 'in_treatment', 'accepted']),
    ).scalar() or 0

    return slugs, overdue, risk_open, risk_total


# ── Endpoints ──

@router.get("/stats", response_model=ComplianceStatsResponse)
def get_stats(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    sections: List[SectionScore] = []
    for section in all_section_keys():
        slugs, overdue, r_open, r_total = _gather_section_inputs(db, section)
        sections.append(compute_section_score(section, slugs, overdue, r_open, r_total))

    n = len(sections)
    if n == 0:
        return ComplianceStatsResponse(
            total_sections=0, mean_global_score=0, mean_coverage_pct=0,
            mean_freshness_pct=0, mean_risks_closed_pct=0, sections=[],
        )
    return ComplianceStatsResponse(
        total_sections=n,
        mean_global_score=round(sum(s.global_score for s in sections) / n, 2),
        mean_coverage_pct=round(sum(s.coverage_pct for s in sections) / n, 2),
        mean_freshness_pct=round(sum(s.freshness_pct for s in sections) / n, 2),
        mean_risks_closed_pct=round(sum(s.risks_closed_pct for s in sections) / n, 2),
        sections=sections,
    )


@router.get("/section/{section_key}", response_model=SectionScore)
def get_section(
    section_key: str,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    if section_key not in SECTIONS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown section '{section_key}'. Valid: {all_section_keys()}",
        )
    slugs, overdue, r_open, r_total = _gather_section_inputs(db, section_key)
    return compute_section_score(section_key, slugs, overdue, r_open, r_total)


@router.get("/scores", response_model=List[ComplianceScoreSnapshot])
def list_snapshots(
    section: Optional[str] = Query(None, pattern="^(pra|pca|pri|sc|fore|test)$"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    q = db.query(ComplianceSectionScore)
    if section:
        q = q.filter(ComplianceSectionScore.section == section)
    q = q.order_by(ComplianceSectionScore.computed_at.desc()).limit(limit)
    return q.all()


# v0.11.3 (R10) — Trend endpoint for sparkline graphs
class TrendPoint(BaseModel):
    computed_at: datetime.datetime
    global_score: float
    coverage_pct: float
    freshness_pct: float
    risks_closed_pct: float


class TrendResponse(BaseModel):
    section: str
    points: List[TrendPoint]
    delta_global: Optional[float] = None
    delta_coverage: Optional[float] = None
    delta_freshness: Optional[float] = None


@router.get("/trend/{section_key}", response_model=TrendResponse)
def get_trend(
    section_key: str,
    days: int = Query(90, ge=1, le=365),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Historique d'évolution d'une section (sparkline data).

    Renvoie les snapshots des `days` derniers jours, ordonnés du plus
    ancien au plus récent. Les deltas (delta_X) comparent la valeur
    actuelle à la valeur d'il y a `days` jours.
    """
    if section_key not in SECTIONS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown section '{section_key}'. Valid: {all_section_keys()}",
        )
    cutoff = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(days=days)
    rows = (
        db.query(ComplianceSectionScore)
        .filter(
            ComplianceSectionScore.section == section_key,
            ComplianceSectionScore.computed_at >= cutoff,
        )
        .order_by(ComplianceSectionScore.computed_at.asc())
        .all()
    )
    points = [
        TrendPoint(
            computed_at=r.computed_at,
            global_score=float(r.global_score),
            coverage_pct=float(r.coverage_pct),
            freshness_pct=float(r.freshness_pct),
            risks_closed_pct=float(r.risks_closed_pct),
        )
        for r in rows
    ]
    delta_g = (points[-1].global_score - points[0].global_score) if len(points) >= 2 else None
    delta_c = (points[-1].coverage_pct - points[0].coverage_pct) if len(points) >= 2 else None
    delta_f = (points[-1].freshness_pct - points[0].freshness_pct) if len(points) >= 2 else None
    return TrendResponse(
        section=section_key,
        points=points,
        delta_global=round(delta_g, 2) if delta_g is not None else None,
        delta_coverage=round(delta_c, 2) if delta_c is not None else None,
        delta_freshness=round(delta_f, 2) if delta_f is not None else None,
    )


@router.post("/snapshot", response_model=List[ComplianceScoreSnapshot])
def persist_snapshot(
    section: Optional[str] = Query(
        None, pattern="^(pra|pca|pri|sc|fore|test)$",
        description="Section to snapshot. None = all 6.",
    ),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Persiste un snapshot dans compliance_section_scores pour l'historique.

    Si section=None, snapshot les 6 sections. Retourne la liste des snapshots créés.
    """
    target_sections = [section] if section else all_section_keys()
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    created: List[ComplianceSectionScore] = []
    for sec in target_sections:
        slugs, overdue, r_open, r_total = _gather_section_inputs(db, sec)
        score = compute_section_score(sec, slugs, overdue, r_open, r_total)
        snap = ComplianceSectionScore(
            section=sec,
            coverage_pct=score.coverage_pct,
            freshness_pct=score.freshness_pct,
            risks_closed_pct=score.risks_closed_pct,
            global_score=score.global_score,
            procedure_count=score.procedure_count,
            subtheme_count=score.subtheme_count,
            subtheme_total=score.subtheme_total,
            risk_open=score.risk_open,
            risk_total=score.risk_total,
            computed_at=now,
            computed_by=user.id if user else None,
        )
        db.add(snap)
        created.append(snap)
    db.commit()
    for s in created:
        db.refresh(s)
    return created
