# app/services/audit_service.py — Ticket #29
# Business logic for cross-mapping data generation and PDF export
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models import Alert, PolicyAcknowledgment, SecurityPolicy, User
from app.models_mapping import FrameworkControl


def build_cross_mapping_data(
    db: Session,
    framework: str,
    period: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Build cross-mapping data with human and technical proofs for each control."""

    # Parse period
    date_from = None
    date_to = None
    if period and ':' in period:
        parts = period.split(':')
        try:
            date_from = datetime.strptime(parts[0], '%Y-%m-%d')
            date_to = datetime.strptime(parts[1], '%Y-%m-%d')
        except ValueError:
            pass

    # Get framework controls
    controls = db.query(FrameworkControl).filter(
        FrameworkControl.framework == framework,
        FrameworkControl.is_active == True,
    ).order_by(FrameworkControl.display_order).all()

    if not controls:
        return []

    # Count total active users for acknowledgment rate
    total_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar() or 1

    # Get policy acknowledgments
    policy_ack_query = db.query(PolicyAcknowledgment)
    if date_from:
        policy_ack_query = policy_ack_query.filter(PolicyAcknowledgment.read_at >= date_from)
    if date_to:
        policy_ack_query = policy_ack_query.filter(PolicyAcknowledgment.read_at <= date_to)
    policy_acks = policy_ack_query.all()

    # Group acks by policy_id
    ack_by_policy: Dict[int, List] = {}
    for ack in policy_acks:
        ack_by_policy.setdefault(ack.policy_id, []).append(ack)

    # Get alerts
    alert_query = db.query(Alert)
    if date_from:
        alert_query = alert_query.filter(Alert.created_at >= date_from)
    if date_to:
        alert_query = alert_query.filter(Alert.created_at <= date_to)
    alerts = alert_query.all()

    alert_count = len(alerts)
    last_alert_date = None
    if alerts:
        latest = max(alerts, key=lambda a: a.created_at if a.created_at else datetime.min)
        if latest.created_at:
            last_alert_date = latest.created_at.isoformat()

    # Build data
    result = []
    for ctrl in controls:
        # Human proof: policy acknowledgment rate
        human_proof = None
        related_policies = []
        if ctrl.category:
            for pol in db.query(SecurityPolicy).filter(
                SecurityPolicy.status.in_(['published', 'approved'])
            ).all():
                if pol.category and pol.category.lower() == ctrl.category.lower():
                    related_policies.append(pol)

        if related_policies:
            total_reads = 0
            total_possible = len(related_policies) * total_users
            for pol in related_policies:
                total_reads += len(ack_by_policy.get(pol.id, []))
            read_rate = round(total_reads / max(total_possible, 1) * 100, 1)
            human_proof = {
                'read_rate': min(read_rate, 100.0),
                'read_count': total_reads,
                'total': total_possible,
            }

        # Technical proof
        technical_proof = {
            'alert_count': alert_count,
            'last_alert_date': last_alert_date,
        }

        # Policy link
        policy_link = None
        if related_policies:
            policy_link = f"/api/v1/governance/policies/{related_policies[0].id}"

        result.append({
            'id': ctrl.id,
            'control_id': ctrl.control_id,
            'title': ctrl.title,
            'description': ctrl.description or '',
            'category': ctrl.category or '',
            'status': 'active',
            'policy_link': policy_link,
            'human_proof': human_proof,
            'technical_proof': technical_proof,
        })

    return result


def generate_cross_mapping_pdf(
    data: List[Dict[str, Any]],
    framework: str,
    period: Optional[str] = None,
) -> bytes:
    """Generate a PDF report of cross-mapping data using fpdf2."""

    from fpdf import FPDF

    class PDF(FPDF):
        def header(self):
            self.set_font('Helvetica', 'B', 14)
            self.cell(0, 10, f'LogSOC - Audit Cross-Mapping Report', new_x='LMARGIN', new_y='NEXT', align='C')
            self.set_font('Helvetica', '', 10)
            self.cell(0, 6, f'Framework: {framework.upper()}', new_x='LMARGIN', new_y='NEXT', align='C')
            if period:
                self.cell(0, 6, f'Period: {period}', new_x='LMARGIN', new_y='NEXT', align='C')
            self.cell(0, 6, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}', new_x='LMARGIN', new_y='NEXT', align='C')
            self.ln(4)
            self.set_draw_color(0, 102, 204)
            self.set_line_width(0.5)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(4)

        def footer(self):
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(128, 128, 128)
            self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', align='C')

    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Summary section
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Summary', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 9)
    pdf.cell(0, 6, f'Total controls: {len(data)}', new_x='LMARGIN', new_y='NEXT')

    # Count controls with human proofs
    with_human = sum(1 for d in data if d['human_proof'])
    with_policy = sum(1 for d in data if d['policy_link'])
    pdf.cell(0, 6, f'Controls with human proof: {with_human}', new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 6, f'Controls linked to policies: {with_policy}', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(4)

    # Controls detail
    for i, ctrl in enumerate(data):
        if pdf.get_y() > 240:
            pdf.add_page()

        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_fill_color(230, 240, 255)
        pdf.cell(0, 7, f'{ctrl["control_id"]} - {ctrl["title"]}', new_x='LMARGIN', new_y='NEXT', fill=True)

        pdf.set_font('Helvetica', '', 8)
        if ctrl['description']:
            # Truncate long descriptions
            desc = ctrl['description'][:200] + ('...' if len(ctrl['description']) > 200 else '')
            pdf.multi_cell(0, 5, desc)
            pdf.ln(1)

        pdf.set_font('Helvetica', 'B', 8)
        pdf.cell(25, 5, 'Status:', new_x='RIGHT', new_y='LAST')
        pdf.set_font('Helvetica', '', 8)
        pdf.cell(30, 5, ctrl['status'], new_x='LMARGIN', new_y='NEXT')

        # Human proof
        if ctrl['human_proof']:
            hp = ctrl['human_proof']
            pdf.set_font('Helvetica', 'B', 8)
            pdf.cell(25, 5, 'Human proof:', new_x='RIGHT', new_y='LAST')
            pdf.set_font('Helvetica', '', 8)
            pdf.cell(0, 5, f'Read rate: {hp["read_rate"]}%, Ack count: {hp["read_count"]}/{hp["total"]}', new_x='LMARGIN', new_y='NEXT')
        else:
            pdf.set_font('Helvetica', 'B', 8)
            pdf.cell(25, 5, 'Human proof:', new_x='RIGHT', new_y='LAST')
            pdf.set_font('Helvetica', 'I', 8)
            pdf.cell(0, 5, 'No policy linked', new_x='LMARGIN', new_y='NEXT')

        # Technical proof
        tp = ctrl['technical_proof']
        pdf.set_font('Helvetica', 'B', 8)
        pdf.cell(25, 5, 'Technical proof:', new_x='RIGHT', new_y='LAST')
        pdf.set_font('Helvetica', '', 8)
        last_alert = tp['last_alert_date'] or 'N/A'
        pdf.cell(0, 5, f'Alerts: {tp["alert_count"]}, Last alert: {last_alert}', new_x='LMARGIN', new_y='NEXT')

        pdf.ln(3)

    return pdf.output()