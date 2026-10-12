"""Pratiques de sécurité — catalogue, cockpit, cahiers d'audit, actions correctives.

Design (Fabrice 09/09): la pratique FEDÈRE exigences (patterns cibles, zéro IA),
livrables (dérivés), assets (capacités liées) et AUDITS (cahier figé).
Cycle PDCA: audit valide les exigences DANS les documents → constats →
actions correctives (plan d'action existant) → re-audit.

Rôles: RSSI planifie les audits (désigne un user business_role=auditeur),
l'auditeur saisit les constats, la direction lit.
"""
import json
import logging
import re
from datetime import date, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    ReferenceRequirement, GovernanceDeliverable, GovernanceDocument,
    AssetCapability, AssetCmdb, User, GovernanceAction, SecurityPractice,
    PracticePattern, PracticeAudit, PracticeAssetStatus,
)
from app.routers.auth import require_role
from app.roles import match_any

logger = logging.getLogger("logsoc.practices")

router = APIRouter(prefix="/api/v1/grc", tags=["security-practices"])

READ_ROLES = ("admin", "superadmin", "rssi", "dpo", "analyst", "viewer")
EDIT_ROLES = ("admin", "superadmin", "rssi")


# ─── Helpers ──────────────────────────────────────────────────────────────

def _practice_regexes(db: Session):
    """Compile les patterns actifs de chaque pratique. Retourne ({pid: [regex]}, {pid: practice})."""
    by_pid = {}
    pracs = {}
    rows = db.query(PracticePattern, SecurityPractice).join(
        SecurityPractice, SecurityPractice.id == PracticePattern.practice_id).filter(
        PracticePattern.is_active == True,  # noqa: E712
        SecurityPractice.is_active == True).all()  # noqa: E712
    for pat, prac in rows:
        try:
            rx = re.compile(pat.pattern, re.I)
        except re.error:
            continue
        by_pid.setdefault(prac.id, []).append(rx)
        pracs[prac.id] = prac
    return by_pid, pracs


def _practice_of_requirement(r, by_pid):
    """La pratique dominante d'une exigence (max de matches patterns), ou None."""
    t = ((r.target or "") + " " + (r.rule or "")[:150]).lower()
    scores = {}
    for pid, rxs in by_pid.items():
        n = sum(len(rx.findall(t)) for rx in rxs)
        if n:
            scores[pid] = n
    if not scores:
        return None
    return max(scores.items(), key=lambda x: x[1])[0]


def _requirements_of_practice(practice_id: int, db: Session):
    """Les exigences d'une pratique — résolution DYNAMIQUE (jamais persistée).
    2 sources (BP v2 13/09, additifs):
    1. patterns v1 (regex sur target+rule)
    2. GOUVERNANCE: pratique dérivée de la matrice -> exigences des livrables
       de la sous-catégorie (jointure déterministe livrable->practice.name)
    """
    by_pid, pracs = _practice_regexes(db)
    reqs = db.query(ReferenceRequirement).filter(
        ReferenceRequirement.entry_type == "requirement").all()
    if practice_id in by_pid:
        # source patterns v1
        v1 = [r for r in reqs if _practice_of_requirement(r, by_pid) == practice_id]
    else:
        v1 = []
    # source gouvernance v2: mapping explicite (practice_subcategory_links)
    # — couvre le pilote, les fusions v1 et les créations (13/09g)
    from app.models import PracticeSubcategoryLink
    links = db.query(PracticeSubcategoryLink).filter(
        PracticeSubcategoryLink.practice_id == practice_id).all()
    v2 = []
    if links:
        pairs = {(l.driver, l.sub_category) for l in links}
        delivs = db.query(GovernanceDeliverable).filter(
            GovernanceDeliverable.is_active == True,  # noqa: E712
        ).all()
        deliv_ids = {d.id for d in delivs if (d.driver, d.sub_category) in pairs}
        if deliv_ids:
            v2 = [r for r in reqs if r.deliverable_id in deliv_ids]
    # union dédupliquée (une exigence peut venir des 2 sources — transversalité)
    seen = set()
    out = []
    for r in v1 + v2:
        if r.id not in seen:
            seen.add(r.id)
            out.append(r)
    return out


def _facets_of_practice(practice_id: int, db: Session):
    """Calcule les 3 facettes: politique (livrables publiés), réalisation (assets), audit."""
    reqs = _requirements_of_practice(practice_id, db)
    deliv_ids = set(r.deliverable_id for r in reqs if r.deliverable_id)

    docs = {}
    for did in deliv_ids:
        d = db.query(GovernanceDeliverable).filter(GovernanceDeliverable.id == did).first()
        doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == did).first()
        if d:
            docs[did] = {
                "id": did, "name": d.deliverable_name,
                "doc_status": doc.status if doc else None,
                "published": doc.status == "published" if doc else False,
            }
    n_pub = sum(1 for v in docs.values() if v["published"])
    politique = "aucun" if not docs else ("publie" if n_pub > 0 else "en_redaction")

    # Réalisation: capacités CMDB dont le libellé matche les patterns de la pratique
    regexes = _practice_regexes(db)[0].get(practice_id, [])
    caps = db.query(AssetCapability).all()
    cap_names = set()
    for c in caps:
        label = (c.capability or "").replace("_", " ").lower()
        if any(rx.search(label) for rx in regexes):
            cap_names.add(c.capability)
    assets = []
    for cap in cap_names:
        for ac in db.query(AssetCapability).filter(AssetCapability.capability == cap).all():
            a = db.query(AssetCmdb).filter(AssetCmdb.id == ac.asset_id).first()
            if a:
                assets.append({"capability": cap, "asset_id": a.id, "asset_name": a.asset_name})
    realisation = "aucun" if not assets else "present"

    last_audit = db.query(PracticeAudit).filter(
        PracticeAudit.practice_id == practice_id).order_by(
        PracticeAudit.audit_date.desc()).first()
    audit = {
        "last_date": last_audit.audit_date.isoformat() if last_audit else None,
        "verdict": last_audit.verdict if last_audit else None,
        "audit_id": last_audit.id if last_audit else None,
    }
    return {
        "politique": {"status": politique, "published_count": n_pub, "livrables": list(docs.values())},
        "realisation": {"status": realisation, "assets": assets[:10]},
        "audit": audit,
        "exigences_count": len(reqs),
    }


# ─── Schemas ───────────────────────────────────────────────────────────────

class AuditCreate(BaseModel):
    auditor_user_id: int
    audit_date: Optional[str] = None


class AuditFinding(BaseModel):
    requirement_id: int
    finding: str  # conforme | non_conforme | n_a


class AuditUpdate(BaseModel):
    findings: list[AuditFinding]
    verdict: str
    notes: Optional[str] = None


# ─── Endpoints ─────────────────────────────────────────────────────────────

def _classify_all_requirements(db: Session):
    """UNE SEULE PASSE: classe toutes les exigences -> {practice_id: [reqs]}.
    Evite 22 scans x 2398 exigences x 45 regex (19s -> <1s)."""
    by_pid, pracs = _practice_regexes(db)
    if not by_pid:
        return {}, {}
    reqs = db.query(ReferenceRequirement).filter(
        ReferenceRequirement.entry_type == "requirement").all()
    repartition = {pid: [] for pid in by_pid}
    for r in reqs:
        t = ((r.target or "") + " " + (r.rule or "")[:150]).lower()
        scores = {}
        for pid, rxs in by_pid.items():
            n = 0
            for rx in rxs:
                n += len(rx.findall(t))
            if n:
                scores[pid] = n
        if scores:
            best = max(scores.items(), key=lambda x: x[1])[0]
            repartition[best].append(r)
    return repartition, pracs


@router.get("/practices")
def list_practices(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Liste des pratiques avec facettes et statut agrégé (passe unique)."""
    repartition, pracs = _classify_all_requirements(db)
    practices = db.query(SecurityPractice).filter(
        SecurityPractice.is_active == True).all()  # noqa: E712

    # Livrables publies par livrable (une seule requete)
    docs_by_deliv = {}
    for doc in db.query(GovernanceDocument).all():
        docs_by_deliv[doc.deliverable_id] = doc.status

    # Audits: dernier par pratique (une seule requete)
    last_audits = {}
    for a in db.query(PracticeAudit).order_by(PracticeAudit.audit_date.desc(),
                                              PracticeAudit.id.desc()).all():
        if a.practice_id not in last_audits:
            last_audits[a.practice_id] = a

    # Capacites matchees par pratique (heuristique libelle)
    cap_rows = db.query(AssetCapability).all()
    out = []
    for p in practices:
        reqs = repartition.get(p.id, [])
        deliv_ids = set(r.deliverable_id for r in reqs if r.deliverable_id)
        n_pub = sum(1 for did in deliv_ids if docs_by_deliv.get(did) == "published")
        politique = "aucun" if not deliv_ids else ("publie" if n_pub > 0 else "en_redaction")
        regexes = _practice_regexes(db)[0].get(p.id, [])
        cap_names = set()
        for cp in cap_rows:
            label = (cp.capability or "").replace("_", " ").lower()
            if any(rx.search(label) for rx in regexes):
                cap_names.add(cp.capability)
        realisation = "present" if cap_names else "aucun"

        a = last_audits.get(p.id)
        audit_verdict = a.verdict if a else None
        audit_date = a.audit_date.isoformat() if a else None

        if audit_verdict == "non_conforme":
            status = "a_corriger"
        elif audit_verdict and audit_verdict != "en_cours":
            status = "verifie"
        elif politique == "publie" and realisation == "present":
            status = "deployee"
        elif politique == "aucun":
            status = "non_couverte"
        else:
            status = "en_cours"
        out.append({
            "id": p.id, "code": p.code, "name": p.name, "family": p.family,
            "exigences_count": len(reqs),
            "politique": politique,
            "published_count": n_pub,
            "realisation": realisation,
            "audit": audit_verdict,
            "audit_date": audit_date,
            "status": status,
            "audit_frequency": p.audit_frequency or "non_defini",
        })
    return {"items": out, "total": len(out)}


@router.get("/practices/{practice_id}")
def get_practice(
    practice_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Cockpit complet: exigences groupées par livrable + facettes + audits."""
    p = db.query(SecurityPractice).filter(SecurityPractice.id == practice_id).first()
    if not p:
        raise HTTPException(404, "Pratique introuvable")
    f = _facets_of_practice(practice_id, db)
    reqs = _requirements_of_practice(practice_id, db)
    groups = {}
    for r in reqs:
        did = r.deliverable_id or 0
        groups.setdefault(did, []).append({
            "id": r.id, "ref_id": r.ref_id, "rule": (r.rule or "")[:400],
            "target": r.target, "criticality": r.criticality,
            "compliance_status": r.compliance_status,
            "framework": r.regulatory_framework,
        })
    deliv_names = {d.id: d.deliverable_name for d in db.query(GovernanceDeliverable).all()}
    exigences_par_livrable = [
        {"deliverable_id": did,
         "deliverable_name": deliv_names.get(did, "Sans livrable (technique)"),
         "count": len(items), "items": items}
        for did, items in sorted(groups.items(), key=lambda x: -len(x[1]))
    ]
    audits = db.query(PracticeAudit).filter(
        PracticeAudit.practice_id == practice_id).order_by(
        PracticeAudit.audit_date.desc()).limit(10).all()
    return {
        "id": p.id, "code": p.code, "name": p.name, "family": p.family,
        "description": p.description,
        "exigences_count": f["exigences_count"],
        "exigences_par_livrable": exigences_par_livrable,
        "politique": f["politique"],
        "realisation": f["realisation"],
        "audits": [{
            "id": a.id, "audit_date": a.audit_date.isoformat(),
            "auditor_name": a.auditor_name, "verdict": a.verdict,
            "status": a.status, "actions_generated": a.actions_generated,
        } for a in audits],
    }


class AssetStatusIn(BaseModel):
    status: str  # conforme | non_conforme | non_applicable


@router.get("/practices/{practice_id}/assets")
def practice_assets(
    practice_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Assets support de la pratique (via capacités ↔ patterns) + déclarations
    terrain (practice_asset_status). Vue de complétion pour Opérations."""
    p = db.query(SecurityPractice).filter(SecurityPractice.id == practice_id).first()
    if not p:
        raise HTTPException(404, "Pratique introuvable")
    regexes = _practice_regexes(db)[0].get(practice_id, [])
    caps = db.query(AssetCapability).all()
    cap_names = set()
    for c in caps:
        label = (c.capability or "").replace("_", " ").lower()
        if any(rx.search(label) for rx in regexes):
            cap_names.add(c.capability)
    # assets portant ces capacités
    asset_map = {}
    for cap in cap_names:
        for ac in db.query(AssetCapability).filter(AssetCapability.capability == cap).all():
            asset_map.setdefault(ac.asset_id, set()).add(cap)
    # déclarations terrain existantes
    statuses = {s.asset_id: s for s in db.query(PracticeAssetStatus).filter(
        PracticeAssetStatus.practice_id == practice_id).all()}
    items = []
    for aid, capset in asset_map.items():
        a = db.query(AssetCmdb).filter(AssetCmdb.id == aid).first()
        if not a:
            continue
        s = statuses.get(aid)
        items.append({
            "asset_id": aid,
            "asset_name": a.asset_name,
            "asset_type": getattr(a, "asset_type", None),
            "capabilities": sorted(capset),
            "status": s.status if s else None,
            "updated_by": s.updated_by if s else None,
            "updated_at": s.updated_at.isoformat() if s and s.updated_at else None,
        })
    items.sort(key=lambda x: x["asset_name"])
    return {"practice_id": practice_id, "items": items, "total": len(items)}


@router.put("/practices/{practice_id}/assets/{asset_id}")
def declare_asset_status(
    practice_id: int,
    asset_id: int,
    body: AssetStatusIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Déclaration TERRAIN: l'équipe technique déclare l'état d'une pratique
    sur un asset (saisie rapide, 1 par paire — pas exigence par exigence).
    Ouvert aux membres des services porteurs de la pratique + rôles forts."""
    if body.status not in ("conforme", "non_conforme", "non_applicable"):
        raise HTTPException(400, "Statut invalide: conforme | non_conforme | non_applicable")
    p = db.query(SecurityPractice).filter(SecurityPractice.id == practice_id).first()
    if not p:
        raise HTTPException(404, "Pratique introuvable")
    a = db.query(AssetCmdb).filter(AssetCmdb.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Asset introuvable")
    # droits: rôles forts OU membre d'un service porteur d'un livrable de la pratique
    from app.service_access import is_strong_role, get_user_service_ids
    from app.models import PracticeSubcategoryLink, GovernanceDeliverable
    if not is_strong_role(current_user):
        links = db.query(PracticeSubcategoryLink).filter(
            PracticeSubcategoryLink.practice_id == practice_id).all()
        pairs = {(l.driver, l.sub_category) for l in links}
        svc_ids = {d.service_id for d in db.query(GovernanceDeliverable).filter(
            GovernanceDeliverable.is_active == True).all()  # noqa: E712
            if (d.driver, d.sub_category) in pairs and d.service_id}
        if not (svc_ids & get_user_service_ids(db, current_user)):
            raise HTTPException(403, "Seuls les membres des services porteurs de la pratique peuvent déclarer")
    s = db.query(PracticeAssetStatus).filter(
        PracticeAssetStatus.practice_id == practice_id,
        PracticeAssetStatus.asset_id == asset_id,
    ).first()
    if not s:
        s = PracticeAssetStatus(practice_id=practice_id, asset_id=asset_id)
        db.add(s)
    s.status = body.status
    s.updated_by = current_user.username
    db.commit()
    db.refresh(s)
    return {"ok": True, "status": s.status, "updated_by": s.updated_by,
            "updated_at": s.updated_at.isoformat() if s.updated_at else None}


@router.post("/practices/{practice_id}/audits")
def create_audit(
    practice_id: int,
    body: AuditCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """RSSI planifie un audit: fige le périmètre (exigences par livrable) et désigne l'auditeur."""
    p = db.query(SecurityPractice).filter(SecurityPractice.id == practice_id).first()
    if not p:
        raise HTTPException(404, "Pratique introuvable")
    auditor = db.query(User).filter(User.id == body.auditor_user_id).first()
    if not auditor:
        raise HTTPException(404, "Auditeur introuvable")
    reqs = _requirements_of_practice(practice_id, db)
    perimeter = [{"requirement_id": r.id, "deliverable_id": r.deliverable_id} for r in reqs]
    audit = PracticeAudit(
        practice_id=practice_id,
        auditor_user_id=auditor.id,
        auditor_name=auditor.display_name or auditor.username,
        audit_date=body.audit_date or date.today().isoformat(),
        perimeter=json.dumps(perimeter),
        verdict="en_cours",
        status="en_cours",
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)
    return {"id": audit.id, "perimeter_count": len(perimeter),
            "auditor": audit.auditor_name,
            "audit_date": audit.audit_date.isoformat(),
            "message": "Cahier d'audit créé — périmètre figé"}


@router.get("/practice-audits/{audit_id}")
def get_audit(
    audit_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Le cahier d'audit: périmètre figé groupé par livrable + constats existants."""
    a = db.query(PracticeAudit).filter(PracticeAudit.id == audit_id).first()
    if not a:
        raise HTTPException(404, "Audit introuvable")
    perimeter = json.loads(a.perimeter or "[]")
    findings = json.loads(a.findings or "{}")
    deliv_names = {d.id: d.deliverable_name for d in db.query(GovernanceDeliverable).all()}
    req_ids = [x["requirement_id"] for x in perimeter]
    reqs = {}
    if req_ids:
        for r in db.query(ReferenceRequirement).filter(
                ReferenceRequirement.id.in_(req_ids)).all():
            reqs[r.id] = r
    groups = {}
    for x in perimeter:
        did = x["deliverable_id"] or 0
        r = reqs.get(x["requirement_id"])
        if not r:
            continue
        groups.setdefault(did, []).append({
            "requirement_id": r.id, "ref_id": r.ref_id,
            "rule": (r.rule or "")[:400], "target": r.target,
            "criticality": r.criticality,
            "finding": findings.get(str(r.id)),
        })
    cahier = [
        {"deliverable_id": did,
         "deliverable_name": deliv_names.get(did, "Sans livrable"),
         "count": len(items), "items": items}
        for did, items in sorted(groups.items(), key=lambda x: -len(x[1]))
    ]
    return {
        "id": a.id, "practice_id": a.practice_id,
        "audit_date": a.audit_date.isoformat(), "auditor_name": a.auditor_name,
        "verdict": a.verdict, "status": a.status, "notes": a.notes,
        "actions_generated": a.actions_generated,
        "cahier": cahier,
        # ── Rapport signé (10/09) ──
        "report_path": a.report_path,
        "report_signed": a.report_signed,
        "report_signed_by": a.report_signed_by,
        "report_signed_at": a.report_signed_at.isoformat() if a.report_signed_at else None,
        "report_sha256": a.report_sha256,
        "direction_notified_at": a.direction_notified_at.isoformat() if a.direction_notified_at else None,
    }


@router.put("/practice-audits/{audit_id}")
def update_audit(
    audit_id: int,
    body: AuditUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """L'auditeur saisit les constats ligne par ligne + le verdict global."""
    a = db.query(PracticeAudit).filter(PracticeAudit.id == audit_id).first()
    if not a:
        raise HTTPException(404, "Audit introuvable")
    if a.status == "clos":
        raise HTTPException(409, "Audit clos — constats non modifiables")
    if a.actions_generated:
        raise HTTPException(409, "Actions déjà générées — constats figés")
    findings = json.loads(a.findings or "{}")
    for f in body.findings:
        if f.finding not in ("conforme", "non_conforme", "n_a"):
            raise HTTPException(400, f"Constat invalide: {f.finding}")
        findings[str(f.requirement_id)] = f.finding
    a.findings = json.dumps(findings)
    if body.verdict not in ("conforme", "partiellement_conforme", "non_conforme"):
        raise HTTPException(400, "Verdict invalide")
    a.verdict = body.verdict
    if body.notes is not None:
        a.notes = body.notes
    db.commit()
    n_nc = sum(1 for v in findings.values() if v == "non_conforme")
    return {"id": a.id, "verdict": a.verdict,
            "non_conformes": n_nc,
            "message": f"Constats enregistrés — {n_nc} non conformes"}


@router.post("/practice-audits/{audit_id}/generate-actions")
def generate_actions(
    audit_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Les exigences NON CONFORMES deviennent des actions correctives
    dans le plan d'action existant (governance_actions), puis l'audit est clos.
    Enrichi (10/09): pilot_role = acteur de l'exigence (la tâche va à qui doit
    la corriger), échéance selon criticité (Critique +30j / Majeure +60j /
    Mineure +90j), titre structuré."""
    from app.audit_report import target_date_for_criticality
    from datetime import datetime as _dt, timezone as _tz

    a = db.query(PracticeAudit).filter(PracticeAudit.id == audit_id).first()
    if not a:
        raise HTTPException(404, "Audit introuvable")
    if a.actions_generated:
        raise HTTPException(409, "Actions déjà générées")
    findings = json.loads(a.findings or "{}")
    non_conformes = [int(k) for k, v in findings.items() if v == "non_conforme"]
    if not non_conformes:
        a.status = "clos"
        db.commit()
        return {"created": 0, "message": "Aucune exigence non conforme — audit clos"}
    p = db.query(SecurityPractice).filter(
        SecurityPractice.id == a.practice_id).first()
    reqs = db.query(ReferenceRequirement).filter(
        ReferenceRequirement.id.in_(non_conformes)).all()

    # Acteur → pilot_role: l'exigence porte déjà l'équipe responsable
    def _pilot_of(r):
        actor = (getattr(r, "actor", None) or "").strip()
        if not actor:
            return "RSSI_Gouvernance"
        # mapping acteurs exigences → pilot_role du plan d'action
        amap = {
            "Equipe_Infra_Ops": "RSSI_Gouvernance",  # les actions restent pilotées RSSI;
            "SecOps_CyberTech": "RSSI_Gouvernance",  # l'équipe désignée est dans le titre
            "RSSI_Gouvernance": "RSSI_Gouvernance",
            "DPO": "DPO",
            "RH_Juridique": "rh_juridique",
        }
        return amap.get(actor, "RSSI_Gouvernance")

    created = 0
    for r in reqs:
        crit = (getattr(r, "criticality", None) or "").strip()
        td = target_date_for_criticality(crit, a.audit_date)
        action = GovernanceAction(
            title=(f"[{p.name}] Corriger: {r.ref_id or 'exigence'} — "
                   f"{(r.rule or '')[:60]} (audit du {a.audit_date.strftime('%d/%m/%Y')}"
                   f"{' — prioritaire' if crit == 'Critique' else ''})"),
            description=(f"Action corrective issue de l'audit '{p.name}' "
                         f"du {a.audit_date.isoformat()}.\n"
                         f"Exigence #{r.id}: {(r.rule or '')[:300]}\n"
                         f"Criticité: {crit or 'non définie'} — échéance: {td.isoformat()}\n"
                         f"Acteur désigné: {getattr(r, 'actor', None) or 'non défini'}\n"
                         f"Audit ID: {audit_id}"),
            pilot_role=_pilot_of(r),
            regulatory_framework=r.regulatory_framework or "ANSSI",
            status="a_rediger",
            target_date=_dt.combine(td, _dt.min.time()).replace(tzinfo=_tz.utc),
        )
        db.add(action)
        created += 1
    a.actions_generated = True
    a.status = "clos"
    db.commit()
    return {"created": created,
            "message": (f"{created} actions correctives créées dans le plan d'action "
                        f"(échéances: Critique 30j, Majeure 60j, Mineure 90j)")}

# ─── Rapport d'audit signé (10/09) ─────────────────────────────────────────

class ReportSignBody(BaseModel):
    signer_name: Optional[str] = None   # défaut: nom de l'utilisateur connecté


def _can_sign_audit_report(user: User) -> tuple:
    """Le rapport est signé par le RSSI (is_signatory + role d'accès rssi).
    Design Fabrice 10/09: l'auditeur saisit, le RSSI signe, la direction est
    informée SANS validation.
    NOTE: le rôle RSSI est le role d'ACCÈS (users.role='rssi', ex: pixies),
    pas le business_role (métier). Les deux sont acceptés."""
    if not getattr(user, "is_signatory", False):
        return False, "Vous n'êtes pas déclaré signataire (Administration → Utilisateurs)"
    if (getattr(user, "role", None) or "").lower() == "rssi":
        return True, None
    if match_any(user, ("rssi",)):
        return True, None
    return False, (f"Le rapport d'audit est signé par le RSSI "
                   f"(rôle actuel: {getattr(user, 'role', None) or (getattr(user, 'business_role', None) or '') or 'non défini'})")


@router.post("/practice-audits/{audit_id}/generate-report")
def generate_report(
    audit_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Génère le rapport PDF (fpdf2) depuis le cahier clos. Peut être
    régénéré tant que le rapport n'est pas signé."""
    from app.audit_report import generate_audit_pdf, REPORTS_DIR
    import os
    a = db.query(PracticeAudit).filter(PracticeAudit.id == audit_id).first()
    if not a:
        raise HTTPException(404, "Audit introuvable")
    if a.status != "clos":
        raise HTTPException(409, "L'audit doit être clos (constats + verdict + actions) avant de générer le rapport")
    if a.report_signed:
        raise HTTPException(409, "Rapport déjà signé — non régénérable (hash de preuve verrouillé)")
    try:
        path = generate_audit_pdf(a, db)
    except Exception as e:
        logger.error("Report generation failed for audit %d: %s", audit_id, repr(e))
        raise HTTPException(500, f"Erreur de génération du rapport: {e}")
    a.report_path = path
    db.commit()
    return {"report_path": os.path.basename(path),
            "message": "Rapport généré — prêt à être signé par le RSSI"}


@router.post("/practice-audits/{audit_id}/sign")
def sign_report(
    audit_id: int,
    body: ReportSignBody,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Signature RSSI du rapport (pyHanko, même certificat/circuit que la PSSI).
    Verrouille le rapport: hash de preuve stocké, plus régénérable."""
    from app.audit_report import sign_audit_report
    import os
    a = db.query(PracticeAudit).filter(PracticeAudit.id == audit_id).first()
    if not a:
        raise HTTPException(404, "Audit introuvable")
    if a.report_signed:
        raise HTTPException(409, "Rapport déjà signé")
    ok, err = _can_sign_audit_report(current_user)
    if not ok:
        raise HTTPException(403, err)
    if not a.report_path or not os.path.exists(a.report_path):
        # génération implicite si pas encore fait
        from app.audit_report import generate_audit_pdf
        a.report_path = generate_audit_pdf(a, db)
        db.commit()
    signer_name = body.signer_name or current_user.display_name or current_user.username
    try:
        signed_path, sig_hash = sign_audit_report(
            a.report_path, signer_name, "RSSI")
    except Exception as e:
        logger.error("Report signing failed for audit %d: %s", audit_id, repr(e))
        raise HTTPException(500, f"Erreur de signature: {e}")
    a.report_signed_path = signed_path
    a.report_signed = True
    a.report_signed_by = signer_name
    a.report_signed_at = datetime.now(timezone.utc)
    a.report_sha256 = sig_hash
    db.commit()
    return {"signed": True, "signed_by": signer_name, "sha256": sig_hash,
            "message": "Rapport signé — prêt à informer la direction"}


@router.post("/practice-audits/{audit_id}/notify-direction")
def notify_direction(
    audit_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Email d'INFORMATION à la direction avec le rapport signé en PJ.
    PAS de validation — le circuit unanimité est réservé aux livrables.
    Destinataires: business_role ∈ (gerant, president, dg, direction)."""
    from app.routers.settings_smtp import send_email
    import os

    a = db.query(PracticeAudit).filter(PracticeAudit.id == audit_id).first()
    if not a:
        raise HTTPException(404, "Audit introuvable")
    if not a.report_signed:
        raise HTTPException(409, "Le rapport doit être signé avant d'informer la direction")
    p = db.query(SecurityPractice).filter(
        SecurityPractice.id == a.practice_id).first()

    candidates = db.query(User).filter(
        User.business_role.isnot(None),
        User.business_role != "",
        User.is_active == True,  # noqa: E712
    ).all()
    direction = [u for u in candidates if match_any(u, ("gerant", "president", "dg", "direction"))]
    if not direction:
        raise HTTPException(404, "Aucun membre de la direction trouvé (business_role gérant/DG/direction)")

    with open(a.report_signed_path, "rb") as f:
        pdf_bytes = f.read()
    filename = f"Rapport-audit-{p.code if p else 'pratique'}-{a.audit_date.isoformat()}.pdf"

    verdict_label = {"conforme": "Conforme", "partiellement_conforme": "Partiellement conforme",
                     "non_conforme": "Non conforme", "en_cours": "En cours"}.get(a.verdict, a.verdict)
    findings = json.loads(a.findings or "{}")
    n_nc = sum(1 for v in findings.values() if v == "non_conforme")
    subject = f"[LogSOC] Rapport d'audit signé — {p.name if p else 'pratique'} — verdict: {verdict_label}"
    html = f"""<p>Bonjour,</p>
<p>Le rapport d'audit de la pratique <b>{p.name if p else '?'}</b> (audit du {a.audit_date.strftime('%d/%m/%Y')},
auditeur: {a.auditor_name}) a été signé par {a.report_signed_by}.</p>
<p><b>Verdict: {verdict_label}</b> — {n_nc} exigence(s) non conforme(s).
Le rapport signé est joint à cet email (information, aucune action attendue de votre part).</p>
<p>Empreinte SHA-256 du rapport signé: <code>{a.report_sha256}</code></p>
<p>Cordialement,<br>LogSOC — Gouvernance</p>"""
    text = (f"Rapport d'audit de la pratique '{p.name if p else '?'}' signé par {a.report_signed_by}.\n"
            f"Verdict: {verdict_label} ({n_nc} non conformes).\n"
            f"SHA-256: {a.report_sha256}\n"
            f"Information — aucune action attendue.")

    sent, failed = [], []
    for u in direction:
        to = u.email or u.username
        try:
            send_email(to, subject, html, text_body=text,
                       attachments=[(filename, pdf_bytes)])
            sent.append(u.display_name or u.username)
        except Exception as e:
            logger.warning("Notify direction failed for %s: %s", to, repr(e))
            failed.append(f"{u.display_name or u.username} ({e})")
    a.direction_notified_at = datetime.now(timezone.utc)
    db.commit()
    return {"sent_to": sent, "failed": failed,
            "message": f"Direction informée: {len(sent)} email(s) envoyé(s) avec le rapport signé en pièce jointe"}


@router.get("/practice-audits/{audit_id}/report-file")
def get_report_file(
    audit_id: int,
    signed: bool = Query(True),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Télécharge le PDF du rapport (signé par défaut)."""
    from fastapi.responses import FileResponse
    import os
    a = db.query(PracticeAudit).filter(PracticeAudit.id == audit_id).first()
    if not a:
        raise HTTPException(404, "Audit introuvable")
    path = a.report_signed_path if signed else a.report_path
    if not path or not os.path.exists(path):
        raise HTTPException(404, "Rapport non disponible (générez-le d'abord)")
    p = db.query(SecurityPractice).filter(
        SecurityPractice.id == a.practice_id).first()
    name = f"Rapport-audit-{p.code if p else 'pratique'}-{a.audit_date.isoformat()}"
    fname = f"{name}-signe.pdf" if signed else f"{name}.pdf"
    return FileResponse(path, filename=fname, media_type="application/pdf")

# ─── Re-audit: actions correctives de l'audit précédent (PDCA) ────────────

@router.get("/practices/{practice_id}/previous-actions")
def previous_actions(
    practice_id: int,
    exclude_audit_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Les actions correctives issues des audits précédents de la pratique
    (avant celui en cours). Sert au re-audit: l'auditeur vérifie que les
    corrections de l'audit précédent sont réellement faites (boucle PDCA)."""
    p = db.query(SecurityPractice).filter(
        SecurityPractice.id == practice_id).first()
    if not p:
        raise HTTPException(404, "Pratique introuvable")
    # IDs des audits clos antérieurs de cette pratique
    audits = db.query(PracticeAudit).filter(
        PracticeAudit.practice_id == practice_id,
        PracticeAudit.status == "clos").order_by(
        PracticeAudit.audit_date.desc()).all()
    audit_ids = [a.id for a in audits if exclude_audit_id is None or a.id != exclude_audit_id]
    if not audit_ids:
        return {"items": [], "total": 0}
    # Actions liées à ces audits (traçabilité via "Audit ID: N" dans la description)
    actions = db.query(GovernanceAction).filter(
        GovernanceAction.description.like(f"%[{p.name}]%")).all()
    out = []
    for act in actions:
        m = re.search(r"Audit ID: (\d+)", act.description or "")
        if not m or int(m.group(1)) not in audit_ids:
            continue
        out.append({
            "action_id": act.id,
            "title": act.title,
            "status": act.status,
            "pilot_role": act.pilot_role,
            "target_date": act.target_date.date().isoformat() if act.target_date else None,
            "audit_id": int(m.group(1)),
            "done": act.status in ("valide", "publie"),
        })
    out.sort(key=lambda x: (x["audit_id"], x["action_id"]))
    return {"items": out, "total": len(out)}


# ─── Programme d'audit (menu Audit) ───────────────────────────────────────

@router.get("/audit-program")
def audit_program(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Le programme pluriannuel: chaque pratique avec son echeance.
    Etat: jamais_audite / a_planifier / en_retard / en_cours_saisie."""
    from datetime import date as d
    from dateutil.relativedelta import relativedelta
    from app.config_loader import get as _cfg_get
    # défaut global (13/09): pratiques non_defini héritent de la config générale.
    # LIT LE DISQUE: --workers 2 = chaque worker a son cache CFG, un PUT
    # settings servi par l'un ne recharge pas l'autre
    import yaml as _yaml
    try:
        with open("/opt/logsoc-web/config.yaml") as f:
            _raw = _yaml.safe_load(f) or {}
        default_freq = str((_raw.get("practices") or {}).get("audit_frequency_default", "annuel"))
    except Exception:
        default_freq = "annuel"
    if default_freq not in ("annuel", "biennal", "ponctuel"):
        default_freq = "annuel"
    practices = db.query(SecurityPractice).filter(
        SecurityPractice.is_active == True).all()  # noqa: E712
    out = []
    for p in practices:
        freq = p.audit_frequency or "non_defini"
        # héritage: le réglage explicite de la pratique PRIME sur le défaut global
        eff_freq = freq if freq in ("annuel", "biennal", "ponctuel") else default_freq
        last = db.query(PracticeAudit).filter(
            PracticeAudit.practice_id == p.id).order_by(
            PracticeAudit.audit_date.desc()).first()
        en_cours = db.query(PracticeAudit).filter(
            PracticeAudit.practice_id == p.id,
            PracticeAudit.status == "en_cours").first()

        next_due = None
        if eff_freq in ("annuel", "biennal") and last:
            months = 12 if eff_freq == "annuel" else 24
            next_due = (last.audit_date + relativedelta(months=months))
        if last is None:
            etat = "jamais_audite"
        elif en_cours is not None:
            etat = "en_cours_saisie"
        elif next_due and next_due < d.today():
            etat = "en_retard"
        elif next_due:
            etat = "a_planifier"
        else:
            etat = "clos_ponctuel" if eff_freq == "ponctuel" else "a_planifier"
        out.append({
            "practice_id": p.id, "practice_name": p.name, "family": p.family,
            "audit_frequency": freq,
            "effective_frequency": eff_freq,
            "frequency_source": "pratique" if freq in ("annuel", "biennal", "ponctuel") else "defaut_global",
            "last_audit_date": last.audit_date.isoformat() if last else None,
            "last_verdict": last.verdict if last else None,
            "next_due": next_due.isoformat() if next_due else None,
            "etat": etat,
            "audit_en_cours_id": en_cours.id if en_cours else None,
        })
    # tri: en retard d abord, puis a planifier, puis le reste
    order = {"en_retard": 0, "jamais_audite": 1, "a_planifier": 2, "en_cours_saisie": 3, "clos_ponctuel": 4}
    out.sort(key=lambda x: (order.get(x["etat"], 5), x["next_due"] or "9999"))
    return {"items": out, "total": len(out)}


@router.get("/audit-history")
def audit_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Les audits clos avec verdict et actions generees."""
    audits = db.query(PracticeAudit).filter(
        PracticeAudit.status == "clos").order_by(
        PracticeAudit.audit_date.desc()).limit(100).all()
    out = []
    for a in audits:
        p = db.query(SecurityPractice).filter(
            SecurityPractice.id == a.practice_id).first()
        out.append({
            "id": a.id, "practice_id": a.practice_id,
            "practice_name": p.name if p else "?",
            "audit_date": a.audit_date.isoformat(),
            "auditor_name": a.auditor_name,
            "verdict": a.verdict,
            "actions_generated": a.actions_generated,
        })
    return {"items": out, "total": len(out)}


@router.get("/audit-pending")
def audit_pending(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Les cahiers en cours (a completer par l'auditeur)."""
    audits = db.query(PracticeAudit).filter(
        PracticeAudit.status == "en_cours").order_by(
        PracticeAudit.audit_date.desc()).all()
    out = []
    for a in audits:
        p = db.query(SecurityPractice).filter(
            SecurityPractice.id == a.practice_id).first()
        perimeter = json.loads(a.perimeter or "[]")
        findings = json.loads(a.findings or "{}")
        n_saisis = sum(1 for k in findings if findings[k] in ("conforme", "non_conforme", "n_a"))
        out.append({
            "id": a.id, "practice_id": a.practice_id,
            "practice_name": p.name if p else "?",
            "audit_date": a.audit_date.isoformat(),
            "auditor_name": a.auditor_name,
            "perimeter_count": len(perimeter),
            "saisis_count": n_saisis,
            "verdict": a.verdict,
        })
    return {"items": out, "total": len(out)}


class AuditPrepareBody(BaseModel):
    """Preparation: l'auditeur SELECTIONNE les exigences (jamais de creation).
    Par defaut: toutes celles de la pratique. selected_ids = liste retenue."""
    auditor_user_id: int
    selected_requirement_ids: Optional[list] = None  # None = toutes


@router.post("/practices/{practice_id}/prepare-audit")
def prepare_audit(
    practice_id: int,
    body: AuditPrepareBody,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Preparation du cahier: l'auditeur selectionne les questions parmi les
    exigences de la pratique (par defaut toutes). Le perimetre fige = la selection."""
    p = db.query(SecurityPractice).filter(SecurityPractice.id == practice_id).first()
    if not p:
        raise HTTPException(404, "Pratique introuvable")
    auditor = db.query(User).filter(User.id == body.auditor_user_id).first()
    if not auditor:
        raise HTTPException(404, "Auditeur introuvable")
    all_reqs = _requirements_of_practice(practice_id, db)
    if body.selected_requirement_ids is None:
        reqs = all_reqs
    else:
        wanted = set(body.selected_requirement_ids)
        reqs = [r for r in all_reqs if r.id in wanted]
    if not reqs:
        raise HTTPException(400, "Aucune exigence selectionnee")
    perimeter = [{"requirement_id": r.id, "deliverable_id": r.deliverable_id} for r in reqs]
    audit = PracticeAudit(
        practice_id=practice_id,
        auditor_user_id=auditor.id,
        auditor_name=auditor.display_name or auditor.username,
        audit_date=date.today().isoformat(),
        perimeter=json.dumps(perimeter),
        verdict="en_cours",
        status="en_cours",
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)
    return {"id": audit.id, "perimeter_count": len(perimeter),
            "auditor": audit.auditor_name,
            "audit_date": audit.audit_date.isoformat(),
            "message": f"Cahier cree — {len(perimeter)} exigences selectionnees"}
