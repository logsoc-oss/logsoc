# app/services/crisis_report_service.py — Ticket #54
"""
Crisis report PDF generation service.

Generates a comprehensive PDF report for an archived crisis:
- Header: crisis name, dates, severity, type, final status
- Chronology: full timeline of events
- Actions: completed checklist + who + when + status
- Notifications: authorities notified, stakeholders, send dates
- Contacts mobilized: list of contacts involved
- Post-mortem: analysis of causes, impact, lessons learned
- Vault documents: list of documents consulted
- Signature/validation: RSSI or admin who archived, date
"""
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

logger = logging.getLogger("logsoc.crisis_report")

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False
    logger.warning("fpdf2 not installed, PDF crisis report generation will be unavailable")


def generate_crisis_report_pdf(
    crisis: Dict[str, Any],
    timeline_entries: List[Dict[str, Any]],
    actions: List[Dict[str, Any]],
    notifications: List[Dict[str, Any]],
    contacts: List[Dict[str, Any]],
    postmortem: Optional[Dict[str, Any]],
    vault_docs: List[Dict[str, Any]],
) -> Optional[bytes]:
    """Generate a comprehensive crisis report PDF using fpdf2.

    Returns PDF bytes, or None if fpdf2 is unavailable.
    """
    if not FPDF_AVAILABLE:
        return None

    class CrisisPDF(FPDF):
        def header(self):
            self.set_font('Helvetica', 'B', 14)
            self.cell(0, 8, 'Rapport de crise', new_x='LMARGIN', new_y='NEXT')
            self.set_draw_color(200)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(3)

        def footer(self):
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()}/{{nb}} — Genere le {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}',
                      align='C')

    pdf = CrisisPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # ── Header section ──
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Informations generales', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 9)

    crisis_name = crisis.get('summary') or crisis.get('scenario') or f"Crisis #{crisis.get('id', '?')}"
    severity = crisis.get('severity', '—')
    status = crisis.get('status', '—')
    scenario = crisis.get('scenario', '—')

    def fmt_dt(dt):
        if not dt:
            return '—'
        if isinstance(dt, datetime):
            return dt.strftime('%Y-%m-%d %H:%M UTC')
        return str(dt)

    pdf.cell(50, 6, 'Nom:', new_x='RIGHT', new_y='LAST')
    pdf.cell(0, 6, crisis_name, new_x='LMARGIN', new_y='NEXT')
    pdf.cell(50, 6, 'Scenario:', new_x='RIGHT', new_y='LAST')
    pdf.cell(0, 6, scenario, new_x='LMARGIN', new_y='NEXT')
    pdf.cell(50, 6, 'Severite:', new_x='RIGHT', new_y='LAST')
    pdf.cell(0, 6, severity, new_x='LMARGIN', new_y='NEXT')
    pdf.cell(50, 6, 'Statut final:', new_x='RIGHT', new_y='LAST')
    pdf.cell(0, 6, status, new_x='LMARGIN', new_y='NEXT')
    pdf.cell(50, 6, 'Detection:', new_x='RIGHT', new_y='LAST')
    pdf.cell(0, 6, fmt_dt(crisis.get('activated_at')), new_x='LMARGIN', new_y='NEXT')
    pdf.cell(50, 6, 'Containment:', new_x='RIGHT', new_y='LAST')
    pdf.cell(0, 6, fmt_dt(crisis.get('contained_at')), new_x='LMARGIN', new_y='NEXT')
    pdf.cell(50, 6, 'Resolution:', new_x='RIGHT', new_y='LAST')
    pdf.cell(0, 6, fmt_dt(crisis.get('resolved_at')), new_x='LMARGIN', new_y='NEXT')
    pdf.cell(50, 6, 'Archivage:', new_x='RIGHT', new_y='LAST')
    pdf.cell(0, 6, fmt_dt(crisis.get('archived_at')), new_x='LMARGIN', new_y='NEXT')
    pdf.ln(4)

    # ── Chronologie ──
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Chronologie complete', new_x='LMARGIN', new_y='NEXT')
    if timeline_entries:
        for entry in timeline_entries:
            if pdf.get_y() > 250:
                pdf.add_page()
            pdf.set_font('Helvetica', 'B', 9)
            ts = fmt_dt(entry.get('timestamp') or entry.get('created_at'))
            author = entry.get('author') or entry.get('user_id') or '—'
            pdf.cell(0, 6, f'{ts} — {author}', new_x='LMARGIN', new_y='NEXT')
            pdf.set_font('Helvetica', '', 9)
            content = str(entry.get('content', ''))
            pdf.multi_cell(0, 5, content)
            pdf.ln(2)
    else:
        pdf.set_font('Helvetica', 'I', 9)
        pdf.cell(0, 6, 'Aucune entree de timeline.', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(4)

    # ── Actions menées ──
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Actions menées', new_x='LMARGIN', new_y='NEXT')
    if actions:
        for action in actions:
            if pdf.get_y() > 250:
                pdf.add_page()
            pdf.set_font('Helvetica', 'B', 9)
            title = action.get('title', '—')
            astatus = action.get('status', '—')
            assigned = action.get('assigned_to', '—')
            pdf.cell(0, 6, f'{title} [{astatus}] — assigne a: {assigned}',
                     new_x='LMARGIN', new_y='NEXT')
            pdf.set_font('Helvetica', '', 8)
            desc = str(action.get('description', ''))
            if desc:
                pdf.multi_cell(0, 5, desc)
            pdf.ln(2)
    else:
        pdf.set_font('Helvetica', 'I', 9)
        pdf.cell(0, 6, 'Aucune action enregistree.', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(4)

    # ── Notifications envoyées ──
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Notifications envoyees', new_x='LMARGIN', new_y='NEXT')
    if notifications:
        for notif in notifications:
            if pdf.get_y() > 250:
                pdf.add_page()
            pdf.set_font('Helvetica', '', 9)
            authority = notif.get('authority', '—')
            regulation = notif.get('regulation', '—')
            nstatus = notif.get('status', '—')
            sent_at = fmt_dt(notif.get('sent_at'))
            pdf.cell(0, 6, f'Autorite: {authority} ({regulation}) — statut: {nstatus} — envoye: {sent_at}',
                     new_x='LMARGIN', new_y='NEXT')
    else:
        pdf.set_font('Helvetica', 'I', 9)
        pdf.cell(0, 6, 'Aucune notification envoyee.', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(4)

    # ── Contacts mobilisés ──
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Contacts mobilises', new_x='LMARGIN', new_y='NEXT')
    if contacts:
        for contact in contacts:
            if pdf.get_y() > 250:
                pdf.add_page()
            pdf.set_font('Helvetica', '', 9)
            name = f"{contact.get('first_name', '')} {contact.get('last_name', '')}".strip()
            if not name:
                name = contact.get('name', '—')
            role = contact.get('role', '—')
            phone = contact.get('phone_pro') or contact.get('phone') or '—'
            email = contact.get('email', '—')
            pdf.cell(0, 6, f'{name} — {role} — Tel: {phone} — Email: {email}',
                     new_x='LMARGIN', new_y='NEXT')
    else:
        pdf.set_font('Helvetica', 'I', 9)
        pdf.cell(0, 6, 'Aucun contact mobilise.', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(4)

    # ── Post-mortem ──
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Post-mortem', new_x='LMARGIN', new_y='NEXT')
    if postmortem:
        pdf.set_font('Helvetica', '', 9)
        fields = [
            ('Ce qui s est passe', 'what_happened'),
            ('Pourquoi', 'why_it_happened'),
            ('Ce qui a fonctionne', 'what_went_well'),
            ('Ce qui a echoue', 'what_went_wrong'),
            ('Lecons apprises', 'lessons_learned'),
            ('Actions correctives', 'corrective_actions'),
            ('Mesures preventives', 'preventive_measures'),
        ]
        for label, key in fields:
            val = postmortem.get(key)
            if val:
                if pdf.get_y() > 250:
                    pdf.add_page()
                pdf.set_font('Helvetica', 'B', 9)
                pdf.cell(0, 6, label + ':', new_x='LMARGIN', new_y='NEXT')
                pdf.set_font('Helvetica', '', 9)
                pdf.multi_cell(0, 5, str(val))
                pdf.ln(2)
    else:
        pdf.set_font('Helvetica', 'I', 9)
        pdf.cell(0, 6, 'Aucun post-mortem enregistre.', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(4)

    # ── Documents du coffre-fort ──
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Documents du coffre-fort consultes', new_x='LMARGIN', new_y='NEXT')
    if vault_docs:
        for doc in vault_docs:
            if pdf.get_y() > 250:
                pdf.add_page()
            pdf.set_font('Helvetica', '', 9)
            name = doc.get('name', '—')
            dtype = doc.get('type', '—')
            pdf.cell(0, 6, f'{name} ({dtype})', new_x='LMARGIN', new_y='NEXT')
    else:
        pdf.set_font('Helvetica', 'I', 9)
        pdf.cell(0, 6, 'Aucun document consulte.', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(6)

    # ── Signature/validation ──
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Signature et validation', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 9)
    archived_by = crisis.get('archived_by', '—')
    pdf.cell(50, 6, 'Archive par (user ID):', new_x='RIGHT', new_y='LAST')
    pdf.cell(0, 6, str(archived_by), new_x='LMARGIN', new_y='NEXT')
    pdf.cell(50, 6, 'Date d archivage:', new_x='RIGHT', new_y='LAST')
    pdf.cell(0, 6, fmt_dt(crisis.get('archived_at')), new_x='LMARGIN', new_y='NEXT')
    pdf.ln(10)
    pdf.set_font('Helvetica', 'I', 8)
    pdf.cell(0, 6, 'Document genere automatiquement par LogSOC SIEM — conforme audit/conformite.',
             new_x='LMARGIN', new_y='NEXT')

    return bytes(pdf.output())