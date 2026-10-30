"""Questionnaires de validation Directions Métiers (13/09).

Deux types: rgpd_processing (inventaire des traitements RGPD — créés/clôturés
par le DPO) et essential_activities (activités essentielles homologation —
RSSI). Le service RÉPOND (membres du service), le créateur du domaine clôture
(décision Fabrice: chacun son domaine).

Flux: brouillon → envoye (email aux membres) → repondu → valide (DPO/RSSI).
"""
import json
import logging
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    BusinessQuestionnaire, QuestionnaireQuestion, QuestionnaireAnswer,
    BusinessService, UserServiceLink, User,
)
from app.routers.auth import require_role

logger = logging.getLogger("logsoc.business_questionnaires")
router = APIRouter()

QTYPES = ("rgpd_processing", "essential_activities")
DOMAIN_ROLES = {"rgpd_processing": "dpo", "essential_activities": "rssi"}


def _domain_guard(qtype: str, current_user: User):
    """Création/clôture: DPO pour le RGPD, RSSI pour l'homologation
    (+ superadmin). Chacun son domaine."""
    role = current_user.role
    if role == "superadmin":
        return
    needed = DOMAIN_ROLES.get(qtype)
    if needed and role != needed:
        raise HTTPException(403, f"Seul le {needed.upper()} gère les questionnaires {qtype}")


def _q_access(q: BusinessQuestionnaire, current_user: User, db: Session):
    """Lecture/réponse: rôles forts, DPO/RSSI (leur domaine) ou MEMBRE du
    service interrogé."""
    role = current_user.role
    if role in ("superadmin", "admin") or role == DOMAIN_ROLES.get(q.qtype):
        return
    link = db.query(UserServiceLink).filter(
        UserServiceLink.user_id == current_user.id,
        UserServiceLink.service_id == q.service_id).first()
    if not link:
        raise HTTPException(403, "Seuls les membres du service peuvent répondre")


class QuestionIn(BaseModel):
    text: str
    qtype: str = "texte"
    options: list[str] | None = None
    prefill: str | None = None
    required: bool = True


class QuestionnaireIn(BaseModel):
    service_id: int
    qtype: str
    title: str | None = None
    questions: list[QuestionIn] | None = None


class AnswersIn(BaseModel):
    answers: dict[int, str]  # question_id -> réponse


# ── Modèles de questions par type (les 2 domaines d'emblée) ──
QUESTION_TEMPLATES = {
    "rgpd_processing": [
        {"text": "Quels traitements de données personnelles votre service réalise-t-il ? (un par ligne : nom, finalité)", "qtype": "texte"},
        {"text": "Quelle est la base légale de chaque traitement ? (consentement, contrat, obligation légale, intérêt légitime...)", "qtype": "texte"},
        {"text": "Quelles catégories de personnes sont concernées ? (clients, employés, prospects...)", "qtype": "texte"},
        {"text": "Quelles catégories de données sont traitées ? (identité, coordonnées, données financières, santé...)", "qtype": "texte"},
        {"text": "Les données sont-elles transmises à des prestataires externes ? Si oui, lesquels ?", "qtype": "texte"},
        {"text": "Les données sortent-elles de l'UE ? Si oui, vers quels pays et sous quelle garantie ?", "qtype": "texte"},
        {"text": "Quelle est la durée de conservation des données ?", "qtype": "texte"},
        {"text": "Un registre des traitements existe-t-il pour votre service ?", "qtype": "booleen"},
    ],
    "essential_activities": [
        {"text": "Quelles sont les activités essentielles de votre service ? (celles dont l'arrêt perturbe l'entreprise)", "qtype": "texte"},
        {"text": "Quels systèmes/applications supportent chaque activité essentielle ?", "qtype": "texte"},
        {"text": "Quelle est la criticité de chaque activité ? (max tolérable d'interruption)", "qtype": "texte"},
        {"text": "Quelles dépendances externes existent ? (prestataires, réseaux, autres services)", "qtype": "texte"},
        {"text": "Existe-t-il des procédures de continuité pour ces activités ?", "qtype": "booleen"},
    ],
}


@router.get("/questionnaires")
def list_questionnaires(
    qtype: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("viewer", "soc_analyst", "auditor", "rssi", "dpo", "compliance_officer", "admin", "superadmin")),
):
    """Liste: chacun voit TOUS (suivi global) — les questionnaires du
    domaine, ou filtrés par qtype."""
    qs = db.query(BusinessQuestionnaire).order_by(BusinessQuestionnaire.created_at.desc())
    if qtype:
        qs = qs.filter(BusinessQuestionnaire.qtype == qtype)
    out = []
    for q in qs.all():
        svc = db.query(BusinessService).filter(BusinessService.id == q.service_id).first()
        n_ans = db.query(QuestionnaireAnswer).filter(
            QuestionnaireAnswer.questionnaire_id == q.id,
            QuestionnaireAnswer.answer.isnot(None)).count()
        n_q = db.query(QuestionnaireQuestion).filter(
            QuestionnaireQuestion.questionnaire_id == q.id).count()
        out.append({
            "id": q.id, "service_id": q.service_id,
            "service_name": svc.name if svc else "?",
            "qtype": q.qtype, "title": q.title, "status": q.status,
            "answered": n_ans, "total_questions": n_q,
            "created_at": q.created_at.isoformat() if q.created_at else None,
            "sent_at": q.sent_at.isoformat() if q.sent_at else None,
            "responded_at": q.responded_at.isoformat() if q.responded_at else None,
        })
    return {"items": out, "total": len(out)}


@router.post("/questionnaires")
def create_questionnaire(
    body: QuestionnaireIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("rssi", "dpo", "admin", "superadmin")),
):
    if body.qtype not in QTYPES:
        raise HTTPException(400, f"qtype invalide: {QTYPES}")
    _domain_guard(body.qtype, current_user)
    svc = db.query(BusinessService).filter(BusinessService.id == body.service_id).first()
    if not svc:
        raise HTTPException(404, "Service introuvable")
    existing = db.query(BusinessQuestionnaire).filter(
        BusinessQuestionnaire.service_id == body.service_id,
        BusinessQuestionnaire.qtype == body.qtype).first()
    if existing:
        raise HTTPException(409, f"Un questionnaire {body.qtype} existe déjà pour ce service (statut: {existing.status})")
    title = body.title or f"{'Inventaire RGPD' if body.qtype == 'rgpd_processing' else 'Activités essentielles'} — {svc.name}"
    q = BusinessQuestionnaire(service_id=body.service_id, qtype=body.qtype,
                              title=title, created_by=current_user.id)
    db.add(q)
    db.flush()
    templates = body.questions or [QuestionIn(**t) for t in QUESTION_TEMPLATES[body.qtype]]
    for pos, qt in enumerate(templates):
        db.add(QuestionnaireQuestion(
            questionnaire_id=q.id, position=pos, text=qt.text, qtype=qt.qtype,
            options=json.dumps(qt.options) if qt.options else None,
            prefill=qt.prefill, required=qt.required))
    db.commit()
    db.refresh(q)
    return {"id": q.id, "title": q.title, "status": q.status, "questions": len(templates)}


@router.get("/questionnaires/{qid}")
def get_questionnaire(
    qid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("viewer", "soc_analyst", "auditor", "rssi", "dpo", "compliance_officer", "admin", "superadmin")),
):
    q = db.query(BusinessQuestionnaire).filter(BusinessQuestionnaire.id == qid).first()
    if not q:
        raise HTTPException(404, "Questionnaire introuvable")
    _q_access(q, current_user, db)
    svc = db.query(BusinessService).filter(BusinessService.id == q.service_id).first()
    questions = db.query(QuestionnaireQuestion).filter(
        QuestionnaireQuestion.questionnaire_id == qid).order_by(
        QuestionnaireQuestion.position).all()
    answers = {a.question_id: a for a in db.query(QuestionnaireAnswer).filter(
        QuestionnaireAnswer.questionnaire_id == qid).all()}
    return {
        "id": q.id, "service_id": q.service_id,
        "service_name": svc.name if svc else "?",
        "qtype": q.qtype, "title": q.title, "status": q.status,
        "created_at": q.created_at.isoformat() if q.created_at else None,
        "sent_at": q.sent_at.isoformat() if q.sent_at else None,
        "responded_at": q.responded_at.isoformat() if q.responded_at else None,
        "validated_at": q.validated_at.isoformat() if q.validated_at else None,
        "questions": [{
            "id": qq.id, "position": qq.position, "text": qq.text,
            "qtype": qq.qtype,
            "options": json.loads(qq.options) if qq.options else None,
            "prefill": qq.prefill, "required": bool(qq.required),
            "answer": answers[qq.id].answer if qq.id in answers else None,
        } for qq in questions],
    }


@router.post("/questionnaires/{qid}/send")
def send_questionnaire(
    qid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("rssi", "dpo", "admin", "superadmin")),
):
    """Passe en 'envoye' — les membres du service le voient dans leur vue.
    (L'email de notification sera branché sur le SMTP existant si souhaité.)"""
    q = db.query(BusinessQuestionnaire).filter(BusinessQuestionnaire.id == qid).first()
    if not q:
        raise HTTPException(404, "Questionnaire introuvable")
    _domain_guard(q.qtype, current_user)
    if q.status != "brouillon":
        raise HTTPException(400, f"Statut actuel: {q.status} — seul un brouillon peut être envoyé")
    q.status = "envoye"
    q.sent_at = datetime.now(timezone.utc)
    db.commit()
    members = db.query(UserServiceLink).filter(UserServiceLink.service_id == q.service_id).count()
    return {"ok": True, "status": "envoye", "members_notified": members}


@router.put("/questionnaires/{qid}/answers")
def submit_answers(
    qid: int,
    body: AnswersIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("viewer", "soc_analyst", "auditor", "rssi", "dpo", "compliance_officer", "admin", "superadmin")),
):
    """Le service répond: membres du service uniquement."""
    q = db.query(BusinessQuestionnaire).filter(BusinessQuestionnaire.id == qid).first()
    if not q:
        raise HTTPException(404, "Questionnaire introuvable")
    _q_access(q, current_user, db)
    if q.status not in ("envoye", "repondu"):
        raise HTTPException(400, f"Statut: {q.status} — le questionnaire n'est pas ouvert aux réponses")
    for question_id, answer in body.answers.items():
        qq = db.query(QuestionnaireQuestion).filter(
            QuestionnaireQuestion.id == question_id,
            QuestionnaireQuestion.questionnaire_id == qid).first()
        if not qq:
            raise HTTPException(404, f"Question {question_id} introuvable")
        a = db.query(QuestionnaireAnswer).filter(
            QuestionnaireAnswer.question_id == question_id).first()
        if not a:
            a = QuestionnaireAnswer(question_id=question_id, questionnaire_id=qid)
            db.add(a)
        a.answer = answer or None
        a.answered_by = current_user.id
    if q.status == "envoye":
        q.status = "repondu"
        q.responded_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True, "status": q.status}


@router.post("/questionnaires/{qid}/validate")
def validate_questionnaire(
    qid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("rssi", "dpo", "admin", "superadmin")),
):
    """Clôture par le domaine: DPO pour rgpd_processing, RSSI pour
    essential_activities (chacun son domaine)."""
    q = db.query(BusinessQuestionnaire).filter(BusinessQuestionnaire.id == qid).first()
    if not q:
        raise HTTPException(404, "Questionnaire introuvable")
    _domain_guard(q.qtype, current_user)
    if q.status != "repondu":
        raise HTTPException(400, f"Statut: {q.status} — le service doit avoir répondu avant validation")
    q.status = "valide"
    q.validated_at = datetime.now(timezone.utc)
    q.validated_by = current_user.id
    db.commit()
    return {"ok": True, "status": "valide",
            "validated_by": current_user.username}