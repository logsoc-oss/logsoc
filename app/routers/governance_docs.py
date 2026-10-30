"""Governance Documents — IA generation + OnlyOffice editing.

Endpoints:
  POST /{deliverable_id}/generate  — IA generates a .docx from requirements
  GET  /{deliverable_id}/file       — serve the .docx file (for OnlyOffice)
  GET  /{deliverable_id}/editor-config — returns OnlyOffice config with JWT
  POST /{deliverable_id}/callback   — OnlyOffice save callback
  GET  /{deliverable_id}/status     — get document status
"""
import os
import json
import logging
import httpx
import jwt
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from typing import Optional
from app.database import get_db
from app.models import GovernanceDeliverable, GovernanceDocument, ReferenceRequirement, DomainSkill, User, PolicyDocument
from app.routers.auth import require_role
from app.config_loader import get as cfg_get, _think_param

logger = logging.getLogger("logsoc.governance_docs")
router = APIRouter()

READ_ROLES = ("admin", "rssi", "dpo", "compliance_officer", "viewer", "auditor")
EDIT_ROLES = ("admin", "rssi", "dpo", "compliance_officer")

DOC_DIR = "/opt/logsoc-web/documents"
ONLYOFFICE_SECRET = "HHdnWf2Ro+af5uPIQT1Nkf3uf/WlrTZhzqbfgYApGSaOadMG"
ONLYOFFICE_URL = "https://127.0.0.1:8443"
BACKEND_URL = "http://127.0.0.1:8000"


import re as _re

def _add_formatted_runs(paragraph, text):
    """Parse inline markdown (bold, italic, code) and add runs to paragraph."""
    # Pattern: **bold**, *italic*, `code`, [link](url)
    pattern = _re.compile(r'(\*\*(.+?)\*\*|\*(.+?)\*|`(.+?)`|\[(.+?)\]\((.+?)\))')
    pos = 0
    for m in pattern.finditer(text):
        if m.start() > pos:
            paragraph.add_run(text[pos:m.start()])
        if m.group(2):  # **bold**
            run = paragraph.add_run(m.group(2))
            run.bold = True
        elif m.group(3):  # *italic*
            run = paragraph.add_run(m.group(3))
            run.italic = True
        elif m.group(4):  # `code`
            run = paragraph.add_run(m.group(4))
            run.font.name = 'Courier New'
            run.font.size = Pt(10)
        elif m.group(5):  # [link](url)
            run = paragraph.add_run(m.group(5))
            run.font.color.rgb = RGBColor(0x05, 0x63, 0xC1)
            run.underline = True
        pos = m.end()
    if pos < len(text):
        paragraph.add_run(text[pos:])


def _markdown_to_docx(docx_doc, markdown_text: str):
    """Convert markdown to python-docx with proper formatting."""
    from docx.shared import Pt, Inches, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn

    lines = markdown_text.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()

        # Skip empty lines
        if not line:
            i += 1
            continue

        # Headings
        if line.startswith('### '):
            h = docx_doc.add_heading(line[4:], level=3)
        elif line.startswith('## '):
            h = docx_doc.add_heading(line[3:], level=2)
        elif line.startswith('# '):
            h = docx_doc.add_heading(line[2:], level=1)
        elif line.startswith('#### '):
            h = docx_doc.add_heading(line[5:], level=4)

        # Horizontal rule → page break
        elif line.startswith('---'):
            docx_doc.add_page_break()

        # Table
        elif line.startswith('|'):
            # Collect all consecutive table lines
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                table_lines.append(lines[i].strip())
                i += 1
            i -= 1  # will be incremented at end

            # Parse table
            rows = []
            for tl in table_lines:
                # Skip separator lines (|---|---|)
                if _re.match(r'^\|[-:\s|]+$', tl):
                    continue
                cells = [c.strip() for c in tl.split('|')[1:-1]]
                rows.append(cells)

            if rows:
                ncols = max(len(r) for r in rows)
                table = docx_doc.add_table(rows=len(rows), cols=ncols)
                table.style = 'Light Grid Accent 1'
                for ri, row in enumerate(rows):
                    for ci, cell in enumerate(row):
                        if ci < ncols:
                            clean = _re.sub(r'\*\*(.+?)\*\*', r'\1', row[ci])
                            clean = _re.sub(r'\*(.+?)\*', r'\1', clean)
                            table.cell(ri, ci).text = clean
                docx_doc.add_paragraph()  # spacing after table

        # Bullet list
        elif line.startswith('- ') or line.startswith('* '):
            p = docx_doc.add_paragraph(style='List Bullet')
            _add_formatted_runs(p, line[2:])

        # Numbered list
        elif _re.match(r'^\d+\.\s', line):
            content = _re.sub(r'^\d+\.\s', '', line)
            p = docx_doc.add_paragraph(style='List Number')
            _add_formatted_runs(p, content)

        # Blockquote
        elif line.startswith('> '):
            p = docx_doc.add_paragraph(line[2:])
            p.paragraph_format.left_indent = Inches(0.5)
            for run in p.runs:
                run.italic = True
                run.font.color.rgb = RGBColor(0x66, 0x66, 0x66)

        # Normal paragraph
        else:
            p = docx_doc.add_paragraph()
            _add_formatted_runs(p, line)

        i += 1


def _call_ollama_for_doc(system_prompt: str, user_prompt: str) -> str:
    """Call Ollama to generate a full document in markdown."""
    ollama_url = cfg_get("ollama.url", "http://127.0.0.1:11434")
    ollama_model = cfg_get("ollama.model", "qwen3:4b")
    ollama_timeout = max(int(cfg_get("ollama.timeout", "30")), 300)
    api_key = cfg_get("ollama.api_key", "")

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    payload = {
        "model": ollama_model,
        "messages": messages,
        "stream": False,
            "think": _think_param(),
        "options": {
            "num_predict": 8192,
            "temperature": float(cfg_get("ollama.temperature", "0.3")),
            "num_ctx": max(int(cfg_get("ollama.context_length", "4096")), 65536),
        },
    }
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    with httpx.Client(timeout=ollama_timeout) as client:
        resp = client.post(
            f"{ollama_url.rstrip('/')}/api/chat",
            json=payload,
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("message", {}).get("content", "")


@router.post("/{deliverable_id}/generate")
def generate_document(
    deliverable_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Generate a .docx document from the deliverable's requirements via IA."""
    # Get deliverable
    deliv = db.query(GovernanceDeliverable).filter(GovernanceDeliverable.id == deliverable_id).first()
    if not deliv:
        raise HTTPException(status_code=404, detail="Deliverable not found")

    # Get skill (assistance)
    skill = db.query(DomainSkill).filter(
        DomainSkill.regulatory_framework == deliv.regulatory_framework,
        DomainSkill.skill_type == "assistance",
    ).first()

    system_prompt = skill.system_prompt if skill else (
        f"Tu es un expert en rédaction de documents de gouvernance SI. "
        f"Rédige un document complet et professionnel pour le livrable '{deliv.deliverable_name}' "
        f"dans le cadre {deliv.regulatory_framework}. "
        f"Le document doit être structuré avec des titres markdown (# ## ###), "
        f"des listes à puces, et un contenu détaillé et professionnel."
    )

    # Get requirements + information + definitions
    reqs = db.query(ReferenceRequirement).filter(
        ReferenceRequirement.deliverable_id == deliverable_id,
        ReferenceRequirement.regulatory_framework == deliv.regulatory_framework,
        ReferenceRequirement.entry_type == "requirement",
    ).all()

    infos = db.query(ReferenceRequirement).filter(
        ReferenceRequirement.deliverable_id == deliverable_id,
        ReferenceRequirement.regulatory_framework == deliv.regulatory_framework,
        ReferenceRequirement.entry_type == "information",
    ).all()

    defs = db.query(ReferenceRequirement).filter(
        ReferenceRequirement.deliverable_id == deliverable_id,
        ReferenceRequirement.regulatory_framework == deliv.regulatory_framework,
        ReferenceRequirement.entry_type == "definition",
    ).all()

    # Get organization profile for context
    org_context = ""
    try:
        from app.models import OrganizationProfile
        profile = db.query(OrganizationProfile).filter(OrganizationProfile.status == "validated").first()
        if profile and profile.profile_data:
            import json as _json_prof
            pd = _json_prof.loads(profile.profile_data) if isinstance(profile.profile_data, str) else profile.profile_data
            org_context = f"""
CONTEXTE DE L'ORGANISATION:
- Nom: {pd.get('name', pd.get('nom', 'N/A'))}
- Secteur: {pd.get('sector', pd.get('secteur', 'N/A'))}
- Employes: {pd.get('employees', pd.get('employes', 'N/A'))}
- Maturite securite: {pd.get('maturity', pd.get('maturite', 'N/A'))}/5
- Cadres reglementaires: {', '.join(pd.get('regulatory_frameworks', pd.get('frameworks', ['N/A'])))}
- Environnement SI: {pd.get('environment', pd.get('environnement', 'N/A'))}
- Outils de securite: {', '.join(pd.get('security_tools', pd.get('outils', ['N/A'])))}
"""
    except Exception:
        pass

    # Build user prompt
    parts = [
        f"Rédige le document complet pour le livrable: \"{deliv.deliverable_name}\"",
        f"Description: {deliv.description or ''}",
        f"Moteur: {deliv.driver}",
        f"Sous-catégorie: {deliv.sub_category}",
        f"Classification: {deliv.classification_level}",
        f"Obligation: {deliv.obligation_level}",
        f"Niveau pyramide: {'Politique' if deliv.pyramid_level == 1 else 'Opérationnel'}",
        f"Pilote: {deliv.realization_role or 'N/A'}",
        org_context,
    ]

    if reqs:
        parts.append(f"\nEXIGENCES À SATISFAIRE ({len(reqs)}):")
        for i, r in enumerate(reqs, 1):
            parts.append(f"{i}. [{r.ref_id or 'N/A'}] {r.rule}")
            if r.target:
                parts.append(f"   Cible: {r.target}")

    if infos:
        parts.append(f"\nINFORMATIONS (matières premières) ({len(infos)}):")
        for i, info in enumerate(infos, 1):
            parts.append(f"{i}. {info.rule}")

    if defs:
        parts.append(f"\nDÉFINITIONS ({len(defs)}):")
        for i, d in enumerate(defs, 1):
            parts.append(f"{i}. {d.rule}")

    parts.append("\nGénère le document COMPLET et DÉTAILLÉ en markdown avec des titres (# ## ###), des sections détaillées, des listes, des tableaux si pertinent. Le document doit être directement utilisable et professionnel. Chaque exigence doit être traitée et développée. Utilise les informations et définitions fournies pour enrichir le contenu. Le document doit faire au minimum 15-20 pages. Adapte le ton et le contenu au profil de l'organisation fourni.")

    user_prompt = '\n'.join(parts)

    # Call IA
    try:
        markdown_content = _call_ollama_for_doc(system_prompt, user_prompt)
    except Exception as e:
        logger.error("Ollama error: %s", e)
        raise HTTPException(status_code=503, detail=f"Erreur IA: {str(e)}")

    if not markdown_content:
        raise HTTPException(status_code=500, detail="IA a retourné un contenu vide")

    # Generate .docx
    from docx import Document as DocxDocument
    docx_doc = DocxDocument()

    # Title page (centered, professional)
    from docx.shared import Pt, Inches, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn

    # Spacer
    for _ in range(6):
        docx_doc.add_paragraph()

    # Title
    title_p = docx_doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_run = title_p.add_run(deliv.deliverable_name)
    title_run.bold = True
    title_run.font.size = Pt(28)
    title_run.font.color.rgb = RGBColor(0x1a, 0x3c, 0x6e)

    # Subtitle
    sub_p = docx_doc.add_paragraph()
    sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub_run = sub_p.add_run(f"Cadre reglementaire: {deliv.regulatory_framework}")
    sub_run.font.size = Pt(14)
    sub_run.font.color.rgb = RGBColor(0x55, 0x55, 0x55)

    # Spacer
    docx_doc.add_paragraph()
    docx_doc.add_paragraph()

    # Info table
    info_table = docx_doc.add_table(rows=6, cols=2)
    info_table.style = 'Light List Accent 1'
    info_data = [
        ("Classification", deliv.classification_level or "Interne"),
        ("Obligation", deliv.obligation_level or "Recommande"),
        ("Pilote", deliv.realization_role or "N/A"),
        ("Verification", deliv.verification_role or "N/A"),
        ("Validation", deliv.validation_role or "N/A"),
        ("Version / Date", f"1.0 — {datetime.now().strftime('%d/%m/%Y')}"),
    ]
    for ri, (label, value) in enumerate(info_data):
        info_table.cell(ri, 0).text = label
        info_table.cell(ri, 1).text = str(value)
        # Bold the label
        for p in info_table.cell(ri, 0).paragraphs:
            for run in p.runs:
                run.bold = True

    docx_doc.add_page_break()

    # Convert markdown to docx
    _markdown_to_docx(docx_doc, markdown_content)

    # Save file
    os.makedirs(DOC_DIR, exist_ok=True)
    file_name = f"{deliverable_id}_{deliv.deliverable_name.replace('/', '_').replace(' ', '_')}.docx"
    file_path = os.path.join(DOC_DIR, file_name)
    docx_doc.save(file_path)

    # Upsert governance_documents record
    existing = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if existing:
        existing.file_name = file_name
        existing.file_path = file_path
        existing.status = "generated"
        # Reset du cycle de signature: la regeneration cree un NOUVEAU contenu,
        # les signatures de l'ancien cycle n'ont plus de valeur
        from app.models import DocumentSignature
        db.query(DocumentSignature).filter(
            DocumentSignature.document_id == existing.id
        ).delete(synchronize_session=False)
        existing.signed = False
        existing.signed_by = None
        existing.signed_at = None
        existing.signature_hash = None
        existing.pdf_path = None
        existing.pdf_generated_at = None
        existing.version += 1
        existing.generated_by_ia = True
        existing.updated_at = datetime.now(timezone.utc)
    else:
        doc_record = GovernanceDocument(
            deliverable_id=deliverable_id,
            file_name=file_name,
            file_path=file_path,
            status="generated",
            version=1,
            generated_by_ia=True,
        )
        db.add(doc_record)
    db.commit()

    # Sync to policy_documents so it appears in Politiques > Documents
    try:
        with open(file_path, 'rb') as f:
            file_bytes = f.read()
        # Check if already exists (by name containing deliverable_id)
        existing_pol = db.query(PolicyDocument).filter(
            PolicyDocument.name == deliv.deliverable_name,
            PolicyDocument.category != 'reference',
        ).first()
        if existing_pol:
            # Update existing
            existing_pol.file_data = file_bytes
            existing_pol.file_name = file_name
            existing_pol.file_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            existing_pol.file_size = len(file_bytes)
            existing_pol.version = str(existing.version if hasattr(existing, 'version') else 1)
            existing_pol.generated_by_ia = True
            existing_pol.status = 'draft'
            existing_pol.regulatory_framework = deliv.regulatory_framework
            existing_pol.classification_level = deliv.classification_level or 'interne'
        else:
            # Create new
            pol_doc = PolicyDocument(
                name=deliv.deliverable_name,
                category='governance',
                version='1.0',
                status='draft',
                description=deliv.description or f"Document généré par IA depuis le livrable {deliv.deliverable_name}",
                file_data=file_bytes,
                file_name=file_name,
                file_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                file_size=len(file_bytes),
                generated_by_ia=True,
                skip_analysis=True,
                regulatory_framework=deliv.regulatory_framework,
            )
            db.add(pol_doc)
        db.commit()
        logger.info("Document synced to policy_documents: %s", deliv.deliverable_name)
    except Exception as e:
        logger.warning("Failed to sync to policy_documents: %s", e)

    logger.info("Document generated for deliverable %d: %s", deliverable_id, file_name)
    return {"status": "ok", "file_name": file_name, "message": "Document généré avec succès"}


@router.get("/{deliverable_id}/file")
def serve_document_file(
    deliverable_id: int,
    db: Session = Depends(get_db),
):
    """Serve the .docx file (accessible by OnlyOffice without auth)."""
    doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if not doc or not os.path.exists(doc.file_path):
        raise HTTPException(status_code=404, detail="Document not found")
    return FileResponse(doc.file_path, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", filename=doc.file_name)


@router.get("/{deliverable_id}/editor-config")
def get_editor_config(
    deliverable_id: int,
    view: bool = False,
    file: str = "docx",
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Return OnlyOffice editor config with JWT signature."""
    doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not generated yet")

    deliv = db.query(GovernanceDeliverable).filter(GovernanceDeliverable.id == deliverable_id).first()
    doc_key = f"logsoc_{deliverable_id}_{doc.version}"
    if file == "pdf":
        doc_url = f"{BACKEND_URL}/api/v1/governance-docs/{deliverable_id}/signed-pdf"
    else:
        doc_url = f"{BACKEND_URL}/api/v1/governance-docs/{deliverable_id}/file"
    callback_url = f"{BACKEND_URL}/api/v1/governance-docs/{deliverable_id}/callback"

    # Un document soumis/signe/publie est FIGE: OnlyOffice en lecture seule
    editable = doc.status in ("generated", "editing", "saved")

    is_pdf_view = (file == "pdf")
    config = {
        "document": {
            "fileType": "pdf" if is_pdf_view else "docx",
            "key": doc_key,
            "title": deliv.deliverable_name if deliv else f"Document_{deliverable_id}",
            "url": doc_url,
            "permissions": {
                "edit": editable,
                "download": True,
                "review": editable,
                "comment": editable,
                "print": True,
            },
        },
        "editorConfig": {
            "mode": "edit" if (editable and not view and not is_pdf_view) else "view",
            "lang": "fr",
            "callbackUrl": callback_url,
            "user": {
                "id": str(current_user.id),
                "name": current_user.username,
            },
            "customization": {
                "forcesave": True,
                "autosave": True,
                "compactHeader": False,
                "toolbarNoTabs": False,
            },
        },
        "documentType": "word",
        "height": "100%",
        "width": "100%",
    }

    # Sign with JWT
    token = jwt.encode(config, ONLYOFFICE_SECRET, algorithm="HS256")

    # OnlyOffice expects the token in the config itself
    config["token"] = token

    return config


@router.post("/{deliverable_id}/callback")
async def onlyoffice_callback(
    deliverable_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    """Handle OnlyOffice save callback."""
    # Verrou: un document soumis/signe ne doit plus etre modifiable.
    # OnlyOffice n'envoie pas de save en mode view, mais on verrouille cote
    # serveur contre un appel direct au callback.
    _doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if _doc and _doc.status not in ("generated", "editing", "saved"):
        logger.warning("Callback ignore: document %d fige (status=%s)", deliverable_id, _doc.status)
        return {"error": 0}
    body = await request.body()
    try:
        data = json.loads(body)
    except:
        data = json.loads(body.decode("utf-8"))

    status = data.get("status")
    logger.info("OnlyOffice callback for deliverable %d: status=%s", deliverable_id, status)

    doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if not doc:
        return {"error": 1}

    # status 2 = ready for saving, 6 = force save, 1 = being edited
    if status in (2, 6):
        url = data.get("url")
        if url:
            try:
                with httpx.Client(timeout=60) as client:
                    resp = client.get(url)
                    resp.raise_for_status()
                    with open(doc.file_path, "wb") as f:
                        f.write(resp.content)
                doc.status = "saved"
                doc.updated_at = datetime.now(timezone.utc)
                db.commit()
                logger.info("Document saved for deliverable %d", deliverable_id)
            except Exception as e:
                logger.error("Error saving document: %s", e)
                return {"error": 1}
    elif status == 1:
        doc.status = "editing"
        db.commit()

    return {"error": 0}


@router.get("/{deliverable_id}/status")
def get_document_status(
    deliverable_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get the current document status (generated, editing, saved)."""
    doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if not doc:
        return {"exists": False, "status": None, "version": 0}
    return {
        "exists": True,
        "status": doc.status,
        "version": doc.version,
        "file_name": doc.file_name,
        "generated_by_ia": doc.generated_by_ia,
        "has_pdf": bool(doc.pdf_path and os.path.exists(doc.pdf_path)),
        "updated_at": doc.updated_at.isoformat() if doc.updated_at else None,
    }

# ── PDF Conversion + Electronic Signature ──

@router.post("/{deliverable_id}/convert-pdf")
def convert_to_pdf(
    deliverable_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Convert the .docx document to PDF using OnlyOffice conversion API."""
    doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if not doc or not os.path.exists(doc.file_path):
        raise HTTPException(status_code=404, detail="Document not found")

    # If PDF already exists and doc not modified since, return cached
    if doc.pdf_path and os.path.exists(doc.pdf_path) and doc.pdf_generated_at and doc.updated_at and doc.pdf_generated_at > doc.updated_at:
        return {"message": "PDF already up-to-date", "pdf_path": doc.pdf_path, "cached": True}

    # Use OnlyOffice conversion API
    # Build the file URL for OnlyOffice to fetch
    file_url = f"{BACKEND_URL}/api/v1/governance-docs/{deliverable_id}/file"
    
    payload = {
        "async": False,
        "filetype": "docx",
        "key": f"pdf_{deliverable_id}_{doc.version}_{int(datetime.now(timezone.utc).timestamp())}",
        "outputtype": "pdf",
        "url": file_url,
        "title": doc.file_name.replace(".docx", ".pdf"),
    }
    
    # Sign the payload with JWT
    token = jwt.encode(payload, ONLYOFFICE_SECRET, algorithm="HS256")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    convert_url = f"{ONLYOFFICE_URL.rstrip('/')}/ConvertService.ashx"
    
    try:
        with httpx.Client(timeout=120, verify=False) as client:
            resp = client.post(convert_url, json=payload, headers=headers)
            resp.raise_for_status()
            # OnlyOffice repond en XML par defaut -> parser en dict
            import xml.etree.ElementTree as ET
            try:
                result = resp.json()
            except Exception:
                root = ET.fromstring(resp.text)
                result = {}
                # normaliser les cles XML (EndConvert, FileUrl...) -> camelCase attendu
                key_map = {"EndConvert": "endConvert", "FileUrl": "fileUrl",
                           "FileType": "fileType", "Percent": "percent", "Error": "error"}
                for child in root:
                    key = key_map.get(child.tag, child.tag[0].lower() + child.tag[1:] if child.tag else child.tag)
                    val = child.text
                    if child.tag == "EndConvert":
                        val = (val or "").lower() in ("true", "1")
                    elif child.tag == "Percent":
                        try: val = int(val)
                        except Exception: pass
                    result[key] = val
        
        if "endConvert" in result and result["endConvert"]:
            pdf_url = result.get("fileUrl")
            if not pdf_url:
                raise HTTPException(status_code=500, detail="No fileUrl in conversion response")
            
            # Download the PDF
            pdf_dir = os.path.dirname(doc.file_path)
            pdf_name = doc.file_name.replace(".docx", ".pdf")
            pdf_path = os.path.join(pdf_dir, pdf_name)
            
            with httpx.Client(timeout=60, verify=False) as client:
                resp = client.get(pdf_url)
                resp.raise_for_status()
                with open(pdf_path, "wb") as f:
                    f.write(resp.content)
            
            # Update DB
            doc.pdf_path = pdf_path
            doc.pdf_generated_at = datetime.now(timezone.utc)
            db.commit()
            
            logger.info("PDF generated for deliverable %d at %s", deliverable_id, pdf_path)
            return {"message": "PDF generated", "pdf_path": pdf_path, "pdf_url": f"{BACKEND_URL}/api/v1/governance-docs/{deliverable_id}/pdf"}
        else:
            # Conversion still in progress (async mode)
            if "percent" in result:
                return {"message": "Conversion in progress", "percent": result["percent"]}
            raise HTTPException(status_code=500, detail="Conversion failed")
    
    except httpx.HTTPStatusError as e:
        logger.error("OnlyOffice conversion error: %s", e)
        raise HTTPException(status_code=502, detail=f"OnlyOffice conversion failed: {e}")


@router.get("/{deliverable_id}/signed-pdf")
def serve_signed_pdf(
    deliverable_id: int,
    db: Session = Depends(get_db),
):
    """Sert le PDF SIGNE (la reference finale). Exige une signature effective."""
    from app.models import DocumentSignature
    doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document introuvable")
    has_sig = db.query(DocumentSignature).filter(
        DocumentSignature.document_id == doc.id
    ).count()
    if not has_sig or not doc.pdf_path or not os.path.exists(doc.pdf_path):
        raise HTTPException(status_code=404, detail="Aucun PDF signe pour ce document")
    base = os.path.splitext(doc.file_name)[0]
    return FileResponse(doc.pdf_path, media_type="application/pdf", filename=f"{base}-signe.pdf")


@router.get("/{deliverable_id}/pdf")
def serve_pdf(
    deliverable_id: int,
    db: Session = Depends(get_db),
):
    """Serve the PDF version of the document (accessible without auth for download)."""
    doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if not doc or not doc.pdf_path or not os.path.exists(doc.pdf_path):
        raise HTTPException(status_code=404, detail="PDF not generated yet")
    return FileResponse(doc.pdf_path, media_type="application/pdf", filename=doc.file_name.replace(".docx", ".pdf"))


@router.post("/{deliverable_id}/submit")
def submit_for_validation(
    deliverable_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Soumet le document a validation: editing/generated -> to_validate.
    Fige le contenu: la conversion PDF doit etre faite apres cela."""
    doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.status in ("signed", "published"):
        raise HTTPException(status_code=400, detail="Document deja signe")
    if doc.status == "to_validate":
        return {"message": "Deja soumis", "status": doc.status}
    doc.status = "to_validate"
    db.commit()
    return {"message": "Soumis a validation", "status": doc.status}


@router.post("/{deliverable_id}/sign")
def sign_document(
    deliverable_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Signature electronique du document (categorie signataire metier).
    Verifie: is_signatory + business_role requis par le livrable.
    Applique une signature PKCS#7 avec cachet visible sur le PDF (pyHanko)."""
    from app.doc_signing import (
        check_sign_permission, sign_pdf, category_label, signatures_complete,
    )
    from app.models import DocumentSignature

    doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.status == "published":
        raise HTTPException(status_code=400, detail="Document deja publie")

    # Deja signe en categorie metier ?
    existing = db.query(DocumentSignature).filter(
        DocumentSignature.document_id == doc.id,
        DocumentSignature.category == "signatory",
    ).first()
    if existing:
        return {"message": "Deja signe (metier)", "signatures": existing.signer_display_name}

    # Droits
    ok, err = check_sign_permission(current_user, doc, db, "signatory")
    if not ok:
        raise HTTPException(status_code=403, detail=err)

    # PDF requis
    if not doc.pdf_path or not os.path.exists(doc.pdf_path):
        raise HTTPException(status_code=400, detail="Generer le PDF d'abord (/convert-pdf)")

    # Signature pyHanko (cachet visible + PKCS#7)
    signed_pdf_path = doc.pdf_path.replace(".pdf", "-signed.pdf")
    signer_name = current_user.display_name or current_user.username
    deliverable = db.query(GovernanceDeliverable).filter(
        GovernanceDeliverable.id == doc.deliverable_id
    ).first()
    doc_label = deliverable.deliverable_name if deliverable else doc.file_name

    # Casquette matchée pour le cachet/audit-trail ('rssi', pas 'dsi / rssi')
    from app.doc_signing import _required_business_role
    from app.roles import first_match
    required = _required_business_role(deliverable) if deliverable else []
    matched_role = first_match(current_user, required, default=current_user.business_role) or ""

    try:
        sig_hash = sign_pdf(
            doc.pdf_path, signed_pdf_path, signer_name,
            matched_role, "signatory", doc_label,
        )
    except Exception as e:
        logger.error("Signature pyHanko failed for doc %d: %s", doc.id, repr(e))
        raise HTTPException(status_code=500, detail=f"Erreur de signature: {e}")

    # Enregistrer
    sig = DocumentSignature(
        document_id=doc.id, category="signatory",
        signer_user_id=current_user.id, signer_display_name=signer_name,
        signer_business_role=matched_role,
        signature_hash=sig_hash, pdf_path=signed_pdf_path,
    )
    db.add(sig)
    doc.signed = True
    doc.signed_by = current_user.id
    doc.signed_at = datetime.now(timezone.utc)
    doc.signature_hash = sig_hash
    doc.pdf_path = signed_pdf_path
    doc.status = "signed" if signatures_complete(doc, db) else "pdf_ready"
    db.commit()

    # Cycle de validation direction: creation des requests + envoi des emails
    validation_sent = 0
    validation_error = None
    try:
        from app.doc_validation import create_validation_cycle, public_link
        from app.routers.settings_smtp import send_email
        cycle, cerr = create_validation_cycle(doc, db)
        if cerr:
            validation_error = cerr
        else:
            deliverable = db.query(GovernanceDeliverable).filter(
                GovernanceDeliverable.id == doc.deliverable_id
            ).first()
            doc_title = deliverable.deliverable_name if deliverable else doc.file_name
            for item in cycle:
                v = item["validator"]
                try:
                    with open(signed_pdf_path, "rb") as f:
                        pdf_content = f.read()
                    pdf_name = os.path.splitext(doc.file_name)[0] + "-signe.pdf"
                    html = f"""<div style="font-family: sans-serif; max-width: 620px; margin: auto; color: #222;">
<h2 style="color: #1f2937; margin-bottom: 4px;">Validation requise — {doc_title}</h2>
<p style="color: #6b7280; font-size: 13px; margin-top: 0;">Document de gouvernance LogSOC — version {doc.version}</p>
<p>Bonjour {v.display_name or v.username},</p>
<p>Le document <strong>{doc_title}</strong> a été signé par <strong>{signer_name}</strong>
({current_user.business_role or 'signataire métier'}).</p>
<p>Votre validation est requise pour sa publication. Vous pouvez :</p>
<p style="text-align: center; margin: 24px 0;">
  <a href="{public_link(item['token'], 'approve')}"
     style="background: #10b981; color: #fff; padding: 12px 28px; border-radius: 8px;
            text-decoration: none; font-weight: 600; display: inline-block; margin: 0 6px;">
     ✅ Valider et publier</a>
  <a href="{public_link(item['token'], 'reject')}"
     style="background: #ef4444; color: #fff; padding: 12px 28px; border-radius: 8px;
            text-decoration: none; font-weight: 600; display: inline-block; margin: 0 6px;">
     ❌ Refuser</a>
</p>
<p style="color: #6b7280; font-size: 12px;">Le PDF signé est joint à cet email.
Ces liens sont personnels et expirent dans 7 jours — aucune connexion n'est nécessaire.</p>
</div>"""
                    text = (f"Validation requise: {doc_title}. "
                            f"Valider: {public_link(item['token'], 'approve')} — "
                            f"Refuser: {public_link(item['token'], 'reject')}")
                    send_email(
                        v.email,
                        f"[LogSOC] Validation requise — {doc_title}",
                        html, text, attachments=[(pdf_name, pdf_content)],
                    )
                    item["request"].email_sent_at = datetime.now(timezone.utc)
                    db.commit()
                    validation_sent += 1
                except Exception as e:
                    logger.warning("Email validation non envoye a %s: %s", v.email, repr(e))
                    validation_error = f"Email non envoyé à {v.email}: {e}"
    except Exception as e:
        validation_error = f"Cycle de validation: {e}"

    return {
        "message": "Document signe (metier)",
        "deliverable_id": deliverable_id,
        "signed_by": current_user.id,
        "signed_by_name": signer_name,
        "signed_at": sig.signed_at.isoformat(),
        "signature_hash": sig_hash,
        "status": doc.status,
        "validation_emails_sent": validation_sent,
        "validation_error": validation_error,
    }


@router.post("/{deliverable_id}/countersign")
def countersign_document(
    deliverable_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Contre-signature direction: verifie business_role gerant/president.
    Quand les 2 categories (signatory + direction) sont presentes -> published."""
    from app.doc_signing import (
        check_sign_permission, sign_pdf, category_label, signatures_complete,
    )
    from app.models import DocumentSignature

    doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.status == "published":
        return {"message": "Deja publie", "status": doc.status}

    # Signature metier requise avant la direction
    has_signatory = db.query(DocumentSignature).filter(
        DocumentSignature.document_id == doc.id,
        DocumentSignature.category == "signatory",
    ).first()
    if not has_signatory:
        raise HTTPException(status_code=400, detail="La signature metier doit etre faite avant la validation direction")

    # Deja contre-signe ?
    existing_dir = db.query(DocumentSignature).filter(
        DocumentSignature.document_id == doc.id,
        DocumentSignature.category == "direction",
    ).first()
    if existing_dir:
        return {"message": "Deja valide par la direction", "signatures": existing_dir.signer_display_name}

    # Droits direction
    ok, err = check_sign_permission(current_user, doc, db, "direction")
    if not ok:
        raise HTTPException(status_code=403, detail=err)

    # PDF source = le PDF deja signe metier
    src_pdf = doc.pdf_path if os.path.exists(doc.pdf_path or "") else None
    if not src_pdf:
        raise HTTPException(status_code=400, detail="PDF signe introuvable")

    signed_pdf_path = src_pdf.replace(".pdf", "-dir.pdf")
    signer_name = current_user.display_name or current_user.username
    deliverable = db.query(GovernanceDeliverable).filter(
        GovernanceDeliverable.id == doc.deliverable_id
    ).first()
    doc_label = deliverable.deliverable_name if deliverable else doc.file_name

    # Casquette matchée pour le cachet/audit-trail ('gerant', pas 'dsi / gerant')
    from app.roles import first_match
    matched_role = first_match(
        current_user, ("gerant", "president", "dg", "direction"),
        default=current_user.business_role,
    ) or ""

    try:
        sig_hash = sign_pdf(
            src_pdf, signed_pdf_path, signer_name,
            matched_role, "direction", doc_label,
        )
    except Exception as e:
        logger.error("Contre-signature pyHanko failed for doc %d: %s", doc.id, repr(e))
        raise HTTPException(status_code=500, detail=f"Erreur de contre-signature: {e}")

    sig = DocumentSignature(
        document_id=doc.id, category="direction",
        signer_user_id=current_user.id, signer_display_name=signer_name,
        signer_business_role=matched_role,
        signature_hash=sig_hash, pdf_path=signed_pdf_path,
    )
    db.add(sig)
    db.flush()  # rendre la signature visible du query AVANT evaluation
    doc.pdf_path = signed_pdf_path
    doc.signature_hash = sig_hash
    if signatures_complete(doc, db):
        doc.status = "published"
    db.commit()

    return {
        "message": "Contre-signature direction enregistree",
        "deliverable_id": deliverable_id,
        "signed_by": signer_name,
        "status": doc.status,
        "signature_hash": sig_hash,
    }


@router.get("/{deliverable_id}/verify")
def verify_document_integrity(
    deliverable_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Verifie l'integrite du PDF signe + listes les signatures."""
    from app.doc_signing import verify_document

    doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return verify_document(doc, db)


@router.get("/{deliverable_id}/signature-info")
def get_signature_info(
    deliverable_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get signature information for a document."""
    doc = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    
    result = {
        "has_pdf": bool(doc.pdf_path and os.path.exists(doc.pdf_path) if doc.pdf_path else False),
        "pdf_generated_at": doc.pdf_generated_at.isoformat() if doc.pdf_generated_at else None,
        "is_signed": bool(doc.signed),
    }
    
    if doc.signed:
        signer = db.query(User).filter(User.id == doc.signed_by).first()
        result["signed_by"] = doc.signed_by
        result["signed_by_name"] = signer.username if signer else None
        result["signed_at"] = doc.signed_at.isoformat() if doc.signed_at else None
        result["signature_hash"] = doc.signature_hash
    
    return result
