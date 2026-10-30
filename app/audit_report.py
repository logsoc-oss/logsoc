"""Rapport d'audit de pratique — génération PDF (fpdf2), signature RSSI (pyHanko),
notification direction (email d'information, PAS de validation).

Design validé Fabrice (10/09):
- Une SEULE signature: le RSSI (is_signatory + business_role rssi) via sign_pdf()
  existant (cachet visible + PKCS#7, certificat PSSI)
- Direction: email D'INFORMATION avec le PDF signé en PJ — pas de validation,
  pas de circuit unanimite (réservé aux livrables type PSSI)
- Le rapport signé = la PREUVE (hash SHA256, rattaché aux exigences du périmètre)

fpdf2 + unicode: les exigences contiennent des accents FR — Helvetica ne les
supporte PAS de façon fiable. Utiliser une police Unicode intégrée à fpdf2
(helvetica est OK pour les caractères latins de base mais échoue sur certains
caractères de source PDFs: "’", "«"...). Solution: sanitizer les textes.
"""
import hashlib
import json
import logging
import os
import re
import unicodedata
from datetime import date, datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import (
    GovernanceAction, GovernanceDeliverable, PracticeAudit,
    ReferenceRequirement, SecurityPractice, User,
)

logger = logging.getLogger("logsoc.audit_report")

REPORTS_DIR = "/opt/logsoc-web/audit_reports"

VERDICT_LABELS = {
    "conforme": "Conforme",
    "partiellement_conforme": "Partiellement conforme",
    "non_conforme": "Non conforme",
    "en_cours": "En cours",
}
FINDING_LABELS = {"conforme": "Conforme", "non_conforme": "Non conforme", "n_a": "N/A"}

# Échéances actions correctives selon criticité (validé Fabrice 10/09)
CRITICALITY_DELAYS = {"Critique": 30, "Majeure": 60, "Mineure": 90}


def _sanitize(s: str) -> str:
    """fpdf2 core-fonts (Helvetica) = latin-1. Remplace les caractères non
    latin-1 par leur équivalent ou '?' pour éviter les UnicodeEncodeError."""
    if not s:
        return ""
    out = []
    for ch in str(s):
        if ch in ("’", "'"):
            out.append("'")
        elif ch in ("«", "»", '"'):
            out.append('"')
        elif ch in ("–", "—", "−"):
            out.append("-")
        elif ch in ("œ", "œ"):
            out.append("oe")
        elif ch in ("Œ", "Œ"):
            out.append("OE")
        elif ch == "\n":
            out.append(" ")
        else:
            try:
                ch.encode("latin-1")
                out.append(ch)
            except UnicodeEncodeError:
                norm = unicodedata.normalize("NFKD", ch)
                repl = "".join(c for c in norm if c.encode("latin-1", "ignore")) or "?"
                out.append(repl)
    return "".join(out)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def target_date_for_criticality(criticality: str, audit_date: date) -> date:
    """Échéance d'une action corrective: Critique +30j, Majeure +60j, Mineure +90j."""
    days = CRITICALITY_DELAYS.get(criticality, 90)
    return audit_date + timedelta(days=days)


def build_audit_report_data(audit: PracticeAudit, db: Session) -> dict:
    """Assemble toutes les données du rapport depuis le cahier clos."""
    p = db.query(SecurityPractice).filter(
        SecurityPractice.id == audit.practice_id).first()
    perimeter = json.loads(audit.perimeter or "[]")
    findings = json.loads(audit.findings or "{}")
    req_ids = [x["requirement_id"] for x in perimeter]
    reqs = {}
    if req_ids:
        for r in db.query(ReferenceRequirement).filter(
                ReferenceRequirement.id.in_(req_ids)).all():
            reqs[r.id] = r
    deliv_names = {d.id: d.deliverable_name for d in db.query(GovernanceDeliverable).all()}

    # Actions générées par cet audit (traçabilité via Audit ID dans description)
    actions = db.query(GovernanceAction).filter(
        GovernanceAction.description.like(f"%Audit ID: {audit.id}%")
    ).all() if req_ids else []

    n_conf = sum(1 for v in findings.values() if v == "conforme")
    n_nc = sum(1 for v in findings.values() if v == "non_conforme")
    n_na = sum(1 for v in findings.values() if v == "n_a")

    # Grouper par livrable
    groups = {}
    for x in perimeter:
        r = reqs.get(x["requirement_id"])
        if not r:
            continue
        did = x.get("deliverable_id") or 0
        g = groups.setdefault(did, {"name": deliv_names.get(did, "Sans livrable"), "items": []})
        g["items"].append({
            "ref_id": r.ref_id or str(r.id),
            "rule": _sanitize((r.rule or "")[:300]),
            "target": _sanitize(r.target or ""),
            "criticality": r.criticality or "",
            "finding": findings.get(str(r.id), ""),
            "framework": r.regulatory_framework or "",
        })

    return {
        "audit_id": audit.id,
        "practice_name": p.name if p else "?",
        "practice_family": p.family if p else "",
        "practice_desc": _sanitize((p.description or "") if p else ""),
        "audit_date": audit.audit_date.isoformat(),
        "auditor_name": audit.auditor_name or "?",
        "verdict": audit.verdict,
        "notes": _sanitize(audit.notes or ""),
        "total": len(perimeter),
        "n_conforme": n_conf, "n_non_conforme": n_nc, "n_na": n_na,
        "groups": groups,
        "actions": [{
            "id": a.id, "title": _sanitize(a.title), "status": a.status,
            "pilot_role": a.pilot_role,
            "target_date": a.target_date.date().isoformat() if a.target_date else None,
        } for a in actions],
    }


def _pdf_footer(pdf, data):
    pdf.set_y(-15)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 8, f"LogSOC - Rapport d'audit #{data['audit_id']} - Page " + "{nb}", align="C")
    pdf.set_text_color(0, 0, 0)


def generate_audit_pdf(audit: PracticeAudit, db: Session) -> str:
    """Génère le PDF du rapport et le stocke. Retourne son chemin."""
    from fpdf import FPDF

    data = build_audit_report_data(audit, db)
    verdict_label = VERDICT_LABELS.get(data["verdict"] or "", data["verdict"] or "?")

    class PDF(FPDF):
        def header(self):
            if self.page_no() == 1:
                return
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(110)
            self.cell(0, 6, f"LogSOC - Rapport d'audit: {data['practice_name']} (#{data['audit_id']})",
                      align="R", new_x="LMARGIN", new_y="NEXT")
            self.set_text_color(0)
            self.set_draw_color(200)
            self.set_line_width(0.3)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(2)

    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=22)

    # ── Page de garde ──
    pdf.add_page()
    pdf.ln(20)
    pdf.set_font("Helvetica", "B", 22)
    pdf.cell(0, 12, "RAPPORT D'AUDIT", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(0, 70, 140)
    pdf.cell(0, 10, data["practice_name"], align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0)
    pdf.ln(6)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Famille: {data['practice_family']}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(14)

    # Encadré infos
    pdf.set_draw_color(0, 70, 140)
    pdf.set_line_width(0.6)
    y0 = pdf.get_y()
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, f"Identifiant du cahier:  AUDIT-{data['audit_id']:04d}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Date de l'audit:  {data['audit_date']}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Auditeur:  {data['auditor_name']}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 9, f"Verdict: {verdict_label.upper()}", new_x="LMARGIN", new_y="NEXT")
    y1 = pdf.get_y()
    pdf.rect(10, y0 - 2, 190, (y1 - y0) + 6)

    # ── Synthèse ──
    pdf.add_page()
    _pdf_footer(pdf, data)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "1. Synthese", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, f"Exigences auditees: {data['total']}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Conformes: {data['n_conforme']}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Non conformes: {data['n_non_conforme']}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Non applicables: {data['n_na']}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Verdict global: {verdict_label}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    if data["notes"]:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Notes de l'auditeur:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5.5, data["notes"])
        pdf.ln(2)
    if data["practice_desc"]:
        pdf.set_font("Helvetica", "I", 8)
        pdf.multi_cell(0, 4.5, data["practice_desc"])
        pdf.ln(2)

    # ── Synthèse par livrable ──
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "2. Resultats par livrable", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    for did, g in sorted(data["groups"].items(), key=lambda x: -len(x[1]["items"])):
        items = g["items"]
        nc = sum(1 for i in items if i["finding"] == "non_conforme")
        conf = sum(1 for i in items if i["finding"] == "conforme")
        na = sum(1 for i in items if i["finding"] == "n_a")
        if pdf.get_y() > 250:
            pdf.add_page()
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(235, 240, 250)
        pdf.cell(0, 6, f"{g['name']}", fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(0, 5, f"  {len(items)} exigences  |  {conf} conformes  |  {nc} non conformes  |  {na} n/a",
                  new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    # ── Détail des constats ──
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "3. Detail des constats", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    for did, g in sorted(data["groups"].items(), key=lambda x: -len(x[1]["items"])):
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(235, 240, 250)
        pdf.cell(0, 6, g["name"], fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        for it in g["items"]:
            if pdf.get_y() > 260:
                pdf.add_page()
            f = FINDING_LABELS.get(it["finding"], it["finding"] or "non renseigne")
            bold = it["finding"] == "non_conforme"
            pdf.set_font("Helvetica", "B" if bold else "", 8)
            ref = f"[{it['ref_id']}] ({it['criticality'] or '-'})" if bold else f"[{it['ref_id']}] ({it['criticality'] or '-'})"
            pdf.set_text_color(180, 30, 30) if bold else pdf.set_text_color(0)
            pdf.cell(0, 5, f"{ref} - {f}  |  cible: {it['target'] or '-'}",
                    new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0)
            pdf.set_font("Helvetica", "", 7.5)
            pdf.multi_cell(0, 4, f"   {it['rule']}")
            pdf.ln(0.8)
        pdf.ln(2)

    # ── Actions correctives ──
    if pdf.get_y() > 240:
        pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "4. Actions correctives", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    if not data["actions"]:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "Aucune action corrective generee (aucune exigence non conforme, ou actions non encore generees).",
                new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(30, 6, "Action", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        for a in data["actions"]:
            if pdf.get_y() > 265:
                pdf.add_page()
            td = a["target_date"] or "-"
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(0, 5, f"ACT-{a['id']:04d}  (echeance {td})  [{a['status']}]", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 7.5)
            pdf.multi_cell(0, 4, f"   {a['title']}")
            pdf.ln(0.8)

    # ── Signatures ──
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "5. Signature", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, "Le rapport d'audit est signe electroniquement par le RSSI.", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, "La direction est informee par email (information, sans validation).", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_draw_color(120)
    pdf.set_line_width(0.4)
    pdf.line(15, pdf.get_y() + 18, 90, pdf.get_y() + 18)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_xy(15, pdf.get_y() + 20)
    pdf.cell(75, 5, "Signature electronique - RSSI (pyHanko PKCS#7)", new_x="LMARGIN", new_y="NEXT")

    os.makedirs(REPORTS_DIR, exist_ok=True)
    out_path = os.path.join(REPORTS_DIR, f"audit-{data['audit_id']:04d}.pdf")
    pdf.output(out_path)
    logger.info("Rapport d'audit genere: %s", out_path)
    return out_path


def sign_audit_report(pdf_path: str, signer_name: str, signer_role: str) -> tuple:
    """Signe le PDF du rapport avec le meme mecanisme que la PSSI (sign_pdf).
    Cachet 'RSSI' + PKCS#7. Retourne (chemin_pdf_signe, hash_sha256)."""
    from app.doc_signing import sign_pdf
    signed_path = pdf_path.replace(".pdf", "-signed.pdf")
    sig_hash = sign_pdf(
        pdf_path, signed_path, signer_name, signer_role,
        category="rssi", doc_label="Rapport d'audit",
    )
    return signed_path, sig_hash