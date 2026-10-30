# app/routers/policy_documents.py — Policy documents library
# Upload (BLOB), download, AI analysis (Ollama), approve, categories, versions, status
# AI wizard: generate per step, finalize document
# Reference import with auto-AI analysis, audit trail, delete for admin
import io
import json
import logging
import httpx
import re
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form, BackgroundTasks, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import get_db, SessionLocal
from app.models import PolicyDocument, PolicyDocumentAudit, PolicyDocumentPage, User, DocumentPreAnalysis
from app.routers.auth import require_role
from app.config_loader import get as cfg_get, _think_param
from jose import jwt as jose_jwt
from app.config import JWT_SECRET, JWT_ALGORITHM

# Track running analysis tasks: {doc_id: True} means stop requested
_analysis_stop_flags: dict = {}

# Analysis queue: only one analysis runs at a time
_analysis_queue: list = []  # list of (doc_id, total_pages, file_data, file_type, file_name)
_analysis_running: bool = False
_analysis_lock = None  # will be created on first use

import asyncio as _asyncio_mod
import threading as _threading_mod

_analysis_thread_lock = _threading_mod.Lock()
_analysis_processor_task = None  # keep ref so GC doesn't cancel the task

logger = logging.getLogger("logsoc.policy_documents")
router = APIRouter()


# ── Schemas ──

class PolicyDocumentUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None


# ── Helpers ──

# Regulatory framework mapping from document organism → framework code.
# This is used at parsing time to stamp each ReferenceRequirement with its
# regulatory_framework (ANSSI, RGPD, NIS2, DORA, ISO27001, Custom).
# The organism field is set at document upload time (ANSSI, CNIL, BSI, ENISA, etc.).
_ORGANISM_TO_FRAMEWORK = {
    "ANSSI": "ANSSI",
    "CNIL": "RGPD",
    "RGPD": "RGPD",
    "GDPR": "RGPD",
    "NIS2": "NIS2",
    "ENISA": "NIS2",
    "DORA": "DORA",
    "EBA": "DORA",
    "ESA": "DORA",
    "ISO": "ISO27001",
    "ISO27001": "ISO27001",
    "BSI": "Custom",
}


def _map_organism_to_framework(organism: str) -> str:
    """Map a document organism string to a regulatory_framework code.
    Case-insensitive prefix match. Returns 'Custom' for unknown organisms."""
    if not organism:
        return "Custom"
    org_upper = organism.upper().strip()
    for key, framework in _ORGANISM_TO_FRAMEWORK.items():
        if org_upper.startswith(key):
            return framework
    return "Custom"


def _get_doc_regulatory_framework(db, doc_id: int) -> str:
    """Get the regulatory_framework for a document.
    Priority: 1) document_pre_analysis table (set by IA pre-analysis)
              2) document.regulatory_framework (set manually at upload)
              3) 'CUSTOM' — ultimate default"""
    # Priority 1: read from document_pre_analysis
    pa = db.query(DocumentPreAnalysis).filter(DocumentPreAnalysis.document_id == doc_id).first()
    if pa and pa.regulatory_framework:
        return pa.regulatory_framework.upper().strip()
    # Priority 2: explicit regulatory_framework on the document
    from app.models import PolicyDocument
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if doc and doc.regulatory_framework and doc.regulatory_framework.upper() != "CUSTOM":
        return doc.regulatory_framework.upper().strip()
    # Priority 3: default
    return "CUSTOM"

VALID_CATEGORIES = {'pssi', 'charter', 'data_gov', 'backup', 'iam', 'other'}
VALID_STATUSES = {'draft', 'approved', 'obsolete'}


def _audit_doc_action(db: Session, doc_id: int, action_type: str, user: Optional[User], details: Optional[str] = None):
    """Record an audit trail entry for a policy document action."""
    entry = PolicyDocumentAudit(
        document_id=doc_id,
        action_type=action_type,
        user_id=user.id if user else None,
        username=user.username if user else None,
        details=details,
    )
    db.add(entry)
    db.commit()


def _doc_to_response(doc: PolicyDocument) -> dict:
    """Convert a PolicyDocument model to a dict (without file_data)."""
    # Dynamic needs_review: check if any done page has different column count from schema
    needs_review = False
    try:
        db = SessionLocal()
        expected_cols = _get_expected_column_count()
        done_pages = db.query(PolicyDocumentPage).filter(
            PolicyDocumentPage.document_id == doc.id,
            PolicyDocumentPage.status == "done"
        ).all()
        for p in done_pages:
            if p.result_text:
                page_cols = _count_columns_in_result(p.result_text)
                if page_cols > 0 and page_cols != expected_cols:
                    needs_review = True
                    break
        db.close()
    except Exception:
        pass

    return {
        'id': doc.id,
        'name': doc.name,
        'category': doc.category,
        'version': doc.version,
        'status': doc.status,
        'description': doc.description,
        'file_name': doc.file_name,
        'file_type': doc.file_type,
        'file_size': doc.file_size,
        'approved_by': doc.approved_by,
        'approved_at': doc.approved_at.isoformat() if doc.approved_at else None,
        'ai_analysis': doc.ai_analysis,
        'ai_analyzed_at': doc.ai_analyzed_at.isoformat() if doc.ai_analyzed_at else None,
        'created_by': doc.created_by,
        'created_at': doc.created_at.isoformat() if doc.created_at else None,
        'updated_at': doc.updated_at.isoformat() if doc.updated_at else None,
        'revision': doc.revision,
        'review_status': doc.review_status,
        'reviewed_by_dsi': doc.reviewed_by_dsi,
        'reviewed_by_direction': doc.reviewed_by_direction,
        'reviewed_dsi_at': doc.reviewed_dsi_at.isoformat() if doc.reviewed_dsi_at else None,
        'reviewed_direction_at': doc.reviewed_direction_at.isoformat() if doc.reviewed_direction_at else None,
        'generated_by_ia': doc.generated_by_ia if doc.generated_by_ia is not None else False,
        'skip_analysis': doc.skip_analysis if doc.skip_analysis is not None else False,
        'organism': doc.organism,
        'country': doc.country,
        'analysis_status': _get_analysis_status(doc.id),
        'requirements_parsed': _has_requirements(doc.id),
        'needs_review': needs_review,
    }

def _has_requirements(doc_id: int) -> bool:
    """Check if requirements have been parsed for this document."""
    try:
        from app.models import ReferenceRequirement
        db = SessionLocal()
        count = db.query(ReferenceRequirement).filter(ReferenceRequirement.document_id == doc_id).count()
        db.close()
        return count > 0
    except Exception:
        return False

def _get_analysis_status(doc_id: int) -> str:
    """Quick analysis status for a document: not_started, pending, analyzing, done, partial"""
    try:
        db = SessionLocal()
        pages = db.query(PolicyDocumentPage).filter(PolicyDocumentPage.document_id == doc_id).all()
        db.close()
        if not pages:
            return 'not_started'
        total = len(pages)
        pending = sum(1 for p in pages if p.status == 'pending')
        analyzing = sum(1 for p in pages if p.status == 'analyzing')
        done = sum(1 for p in pages if p.status == 'done')
        skipped = sum(1 for p in pages if p.status == 'skipped')
        error = sum(1 for p in pages if p.status == 'error')

        # Check if in queue
        in_queue = any(qid == doc_id for (qid, _, _, _, _) in _analysis_queue)

        if analyzing > 0:
            return 'analyzing'
        if pending == total:
            return 'pending' if in_queue else 'not_started'
        if pending == 0 and analyzing == 0:
            if error > 0 and done > 0:
                return 'partial'
            if error > 0 and done == 0:
                return 'error'
            return 'done'
        if pending > 0 and (done + skipped + error) > 0:
            return 'pending' if in_queue else 'paused'
        return 'not_started'
    except Exception:
        return 'not_started'


def _extract_text(file_data: bytes, file_type: str, file_name: str) -> str:
    """Extract text from a document file (PDF, DOCX, TXT)."""
    fname = file_name.lower()

    if fname.endswith('.txt') or file_type == 'text/plain':
        for enc in ('utf-8', 'latin-1', 'cp1252'):
            try:
                return file_data.decode(enc)
            except (UnicodeDecodeError, ValueError):
                continue
        return file_data.decode('utf-8', errors='replace')

    if fname.endswith('.pdf') or file_type == 'application/pdf':
        try:
            from PyPDF2 import PdfReader
            reader = PdfReader(io.BytesIO(file_data))
            pages = []
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    pages.append(text)
            return '\n\n'.join(pages)
        except Exception as e:
            logger.warning("Failed to extract PDF text: %s", e)
            raise HTTPException(status_code=422, detail=f"Cannot extract text from PDF: {e}")

    if fname.endswith('.docx') or 'wordprocessingml' in file_type:
        try:
            from docx import Document
            doc = Document(io.BytesIO(file_data))
            paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
            return '\n\n'.join(paragraphs)
        except Exception as e:
            logger.warning("Failed to extract DOCX text: %s", e)
            raise HTTPException(status_code=422, detail=f"Cannot extract text from DOCX: {e}")

    # Fallback: try as plain text
    try:
        return file_data.decode('utf-8', errors='replace')
    except Exception:
        raise HTTPException(status_code=422, detail=f"Unsupported file type: {file_type}")


async def _ollama_analyze(text: str) -> str:
    """Send text to Ollama for policy analysis.
    Uses /api/chat (not /api/generate) — kimi-k2.6 on Ollama Cloud
    returns empty response with /api/generate but works with /api/chat."""
    from app.routers.ia_prompts import get_prompt as _get_prompt

    ollama_url = cfg_get("ollama.url", "http://127.0.0.1:11434")
    ollama_model = cfg_get("ollama.model", "qwen3:4b")
    ollama_timeout = max(int(cfg_get("ollama.timeout", "30")), 120)

    prompt_template = _get_prompt("document_analysis")
    prompt = prompt_template.replace("{text}", text[:8000])

    payload = {
        "model": ollama_model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
            "think": _think_param(),
        "options": {"num_predict": 2048, "temperature": float(cfg_get("ollama.temperature", "0.1")), "num_ctx": int(cfg_get("ollama.context_length", "4096"))},
    }

    headers = {"Authorization": f"Bearer {cfg_get('ollama.api_key', '')}"} if cfg_get("ollama.api_key", "") else {}
    async with httpx.AsyncClient(timeout=float(ollama_timeout + 10)) as client:
        resp = await client.post(f"{ollama_url.rstrip('/')}/api/chat", json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        msg = data.get("message", {})
        return msg.get("content", "") or data.get("response", "") or "No response from AI"


# ── Endpoints ──

READ_ROLES = ("admin", "rssi", "compliance_officer", "viewer", "auditor", "soc_analyst", "dpo")
EDIT_ROLES = ("admin", "rssi")
ANALYZE_ROLES = ("admin", "rssi", "compliance_officer")

@router.get("/documents")
def list_documents(
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    exclude_reference: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    q = db.query(PolicyDocument)
    if category:
        q = q.filter(PolicyDocument.category == category)
    if status:
        q = q.filter(PolicyDocument.status == status)
    if exclude_reference == "true":
        q = q.filter(PolicyDocument.status != "reference")
    docs = q.order_by(PolicyDocument.created_at.desc()).all()
    return [_doc_to_response(d) for d in docs]


@router.get("/documents/{doc_id}")
def get_document(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return _doc_to_response(doc)


@router.post("/documents")
async def upload_document(
    name: str = Form(...),
    category: str = Form("other"),
    version: str = Form("1.0"),
    status: str = Form("draft"),
    description: Optional[str] = Form(None),
    skip_analysis: bool = Form(False),
    organism: str = Form(""),
    country: str = Form(""),
    regulatory_framework: Optional[str] = Form(None),  # auto-detected by pre-analysis if not provided
    deliverable_id: Optional[int] = Form(None),  # link to governance_deliverable
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    valid_cats = VALID_CATEGORIES | {'reference'}
    if category not in valid_cats:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category. Must be one of: {', '.join(sorted(valid_cats))}"
        )

    valid_statuses = VALID_STATUSES | {'reference'}
    if status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(sorted(valid_statuses))}"
        )

    file_data = await file.read()
    if not file_data:
        raise HTTPException(status_code=400, detail="Empty file")

    is_reference = status == 'reference'

    # Auto-recover pending analyses
    pass  # recovery disabled temporarily

    # Create the document first
    # regulatory_framework: if provided by user, use it; otherwise "CUSTOM"
    # The framework will be determined by pre-analysis IA after upload
    _fw = regulatory_framework if regulatory_framework else "CUSTOM"
    doc = PolicyDocument(
        name=name,
        category=category,
        version=version,
        status=status,
        description=description,
        file_data=file_data,
        file_name=file.filename or "unknown",
        file_type=file.content_type or "application/octet-stream",
        file_size=len(file_data),
        created_by=current_user.id,
        skip_analysis=skip_analysis,
        organism=organism,
        regulatory_framework=_fw,
        country=country if country else None,
        document_type=None,
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    doc_id = doc.id
    _user_id = current_user.id
    _user_name = current_user.username

    # Audit: document imported
    _audit_doc_action(db, doc_id, "imported", current_user, details=f"File: {file.filename}, Size: {len(file_data)}")

    # If deliverable_id provided, link to governance_deliverable
    if deliverable_id and not is_reference:
        try:
            from app.models import GovernanceDeliverable, GovernanceDocument
            deliv = db.query(GovernanceDeliverable).filter(GovernanceDeliverable.id == deliverable_id).first()
            if deliv:
                # Invalidate previous documents linked to this deliverable
                prev_docs = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).all()
                for prev in prev_docs:
                    prev.status = "obsolete"
                # Also invalidate previous policy_documents with same deliverable
                prev_policy = db.query(PolicyDocument).filter(
                    PolicyDocument.category == "governance",
                    PolicyDocument.name == deliv.deliverable_name,
                    PolicyDocument.status != "obsolete"
                ).all()
                for pp in prev_policy:
                    pp.status = "draft"  # invalidate back to draft
                # Set the document name to the deliverable name if not already set
                if not doc.name or doc.name == file.filename:
                    doc.name = deliv.deliverable_name
                    doc.description = deliv.description or doc.description
                # Store file to disk for governance_docs (OnlyOffice needs a file path)
                import os as _os_gov
                _gov_dir = "/opt/logsoc-web/documents"
                _os_gov.makedirs(_gov_dir, exist_ok=True)
                _file_name = f"{deliverable_id}_{deliv.deliverable_name.replace('/', '_').replace(' ', '_')}{_os_gov.path.splitext(file.filename or '')[1]}"
                _file_path = _os_gov.path.join(_gov_dir, _file_name)
                with open(_file_path, "wb") as f_gov:
                    f_gov.write(file_data)
                # Upsert governance_documents
                existing_gov = db.query(GovernanceDocument).filter(GovernanceDocument.deliverable_id == deliverable_id).first()
                if existing_gov:
                    existing_gov.file_name = _file_name
                    existing_gov.file_path = _file_path
                    existing_gov.status = "generated"
                    existing_gov.generated_by_ia = False
                else:
                    gov_doc = GovernanceDocument(
                        deliverable_id=deliverable_id,
                        file_name=_file_name,
                        file_path=_file_path,
                        status="generated",
                        generated_by_ia=False,
                    )
                    db.add(gov_doc)
                db.commit()
                logger.info("Document %d linked to deliverable %d", doc_id, deliverable_id)
        except Exception as e:
            logger.warning("Failed to link document %d to deliverable %d: %s", doc_id, deliverable_id, e)

    if is_reference:
        _file_data = file_data
        _file_type = file.content_type or "application/octet-stream"
        _file_name = file.filename or "unknown"

        # Build response before closing session
        doc_response = _doc_to_response(doc)
        db.close()

        # Launch page-by-page analysis directly (skip slow whole-doc analysis)
        fname_lower = _file_name.lower()
        if fname_lower.endswith('.pdf') or _file_type == 'application/pdf':
            try:
                from PyPDF2 import PdfReader as _PdfReader
                _reader = _PdfReader(io.BytesIO(_file_data))
                _total = len(_reader.pages)
            except Exception:
                _total = 1
        else:
            _total = 1

        # Create page entries
        db_pages = SessionLocal()
        try:
            db_pages.query(PolicyDocumentPage).filter(PolicyDocumentPage.document_id == doc_id).delete()
            for pn in range(1, _total + 1):
                db_pages.add(PolicyDocumentPage(
                    document_id=doc_id,
                    page_number=pn,
                    total_pages=_total,
                    status="pending",
                ))
            db_pages.commit()
            audit_entry = PolicyDocumentAudit(
                document_id=doc_id,
                action_type="imported",
                user_id=_user_id,
                username=_user_name,
                details=f"File: {_file_name}, Pages: {_total}, Model: {cfg_get('ollama.model', 'qwen3:4b')}, URL: {cfg_get('ollama.url', 'localhost')}",
            )
            db_pages.add(audit_entry)
            db_pages.commit()
        except Exception:
            db_pages.rollback()
        finally:
            db_pages.close()

        # Pre-analyze: detect framework + document_type via IA before page analysis
        # Skip if user explicitly provided a framework at upload
        if not skip_analysis and not regulatory_framework:
            try:
                _pre_result = _pre_analyze_framework(SessionLocal(), doc_id)
                _db_pre = SessionLocal()
                try:
                    _doc_pre = _db_pre.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
                    if _doc_pre:
                        _doc_pre.regulatory_framework = _pre_result.get("regulatory_framework", "ANSSI")
                        if _pre_result.get("document_type"):
                            _doc_pre.document_type = _pre_result["document_type"]
                        _db_pre.commit()
                        logger.info("Pre-analysis completed for doc %d: framework=%s, document_type=%s",
                                    doc_id, _pre_result.get("regulatory_framework"), _pre_result.get("document_type"))
                finally:
                    _db_pre.close()
            except Exception as _pre_err:
                logger.warning("Pre-analysis failed for doc %d: %s — proceeding with default framework", doc_id, _pre_err)

        # Enqueue analysis (only one runs at a time) — skip if user opted out
        if not skip_analysis:
            _enqueue_analysis(doc_id, _total, _file_data, _file_type, _file_name)
            # Start processor — keep ref so GC doesn't cancel the task
            global _analysis_processor_task
            _analysis_processor_task = _asyncio_mod.ensure_future(_process_analysis_queue_safe())

        return doc_response
    return _doc_to_response(doc)


@router.put("/documents/{doc_id}")
def update_document(
    doc_id: int,
    body: PolicyDocumentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if body.name is not None:
        doc.name = body.name
    if body.category is not None:
        if body.category not in VALID_CATEGORIES:
            raise HTTPException(status_code=400, detail=f"Invalid category")
        doc.category = body.category
    if body.version is not None:
        doc.version = body.version
    if body.status is not None:
        if body.status not in VALID_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status")
        doc.status = body.status
    if body.description is not None:
        doc.description = body.description

    doc.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(doc)

    # Audit: edited
    _audit_doc_action(db, doc.id, "edited", current_user)

    return _doc_to_response(doc)


@router.post("/documents/{doc_id}/stop-analysis")
def stop_analysis(
    doc_id: int,
    current_user: User = Depends(require_role("admin", "rssi")),
):
    """Stop the page-by-page analysis for a document.
    Sets the stop flag AND removes the doc from the queue so the processor
    won't start it if it hasn't begun yet."""
    _analysis_stop_flags[doc_id] = True

    # Remove from queue if not yet started
    global _analysis_queue
    _analysis_queue = [item for item in _analysis_queue if item[0] != doc_id]

    db = SessionLocal()
    try:
        analyzing = db.query(PolicyDocumentPage).filter(
            PolicyDocumentPage.document_id == doc_id,
            PolicyDocumentPage.status == "analyzing"
        ).all()
        for p in analyzing:
            p.status = "pending"
        db.commit()
    finally:
        db.close()
    return {"status": "stopped", "message": "Analysis stop requested — will halt after current page completes"}


@router.delete("/documents/{doc_id}")
def delete_document(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin",)),
):
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Audit: deleted
    _audit_doc_action(db, doc.id, "deleted", current_user, details=f"Document: {doc.name}")

    # Delete related analysis pages
    db.query(PolicyDocumentPage).filter(PolicyDocumentPage.document_id == doc_id).delete()
    # Delete audit trail
    db.query(PolicyDocumentAudit).filter(PolicyDocumentAudit.document_id == doc_id).delete()
    # Delete stop flag if present
    _analysis_stop_flags.pop(doc_id, None)
    # Remove from queue if present
    global _analysis_queue
    _analysis_queue = [item for item in _analysis_queue if item[0] != doc_id]

    # Cascade: delete requirement-asset links for this doc's requirements
    from app.models import ReferenceRequirement, AssetRequirementLink, ActionPlan
    req_ids = [r.id for r in db.query(ReferenceRequirement).filter(ReferenceRequirement.document_id == doc_id).all()]
    if req_ids:
        db.query(AssetRequirementLink).filter(AssetRequirementLink.requirement_id.in_(req_ids)).delete(synchronize_session=False)
    # Delete requirements
    db.query(ReferenceRequirement).filter(ReferenceRequirement.document_id == doc_id).delete(synchronize_session=False)
    # Delete action plans linked to this doc
    db.query(ActionPlan).filter(ActionPlan.linked_policy_doc_id == doc_id).delete(synchronize_session=False)
    # Delete pre-analysis
    db.query(DocumentPreAnalysis).filter(DocumentPreAnalysis.document_id == doc_id).delete(synchronize_session=False)

    db.delete(doc)
    db.commit()
    return {"ok": True}


@router.get("/documents/{doc_id}/download")
def download_document(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Audit: downloaded
    _audit_doc_action(db, doc.id, "downloaded", current_user)

    return Response(
        content=doc.file_data,
        media_type=doc.file_type,
        headers={
            "Content-Disposition": f'attachment; filename="{doc.file_name}"',
            "Content-Length": str(doc.file_size),
        },
    )


# Recover pending analyses on startup (called once when module is loaded)
# Use a flag to ensure it only runs once

@router.get("/documents/{doc_id}/view")
def view_document(
    doc_id: int,
    token: str = Query(None),
    db: Session = Depends(get_db),
):
    """View document inline (PDF in browser). Accepts token as query param."""
    # Validate token from query param
    if not token:
        raise HTTPException(status_code=401, detail="Token required")
    try:
        payload = jose_jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub") or payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return Response(
        content=doc.file_data,
        media_type=doc.file_type,
        headers={
            "Content-Disposition": f'inline; filename="{doc.file_name}"',
            "Content-Length": str(doc.file_size),
        },
    )


@router.put("/documents/{doc_id}/approve")
def approve_document(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.status == 'approved':
        raise HTTPException(status_code=400, detail="Document already approved")

    doc.status = 'approved'
    doc.approved_by = current_user.id
    doc.approved_at = datetime.now(timezone.utc)
    doc.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(doc)
    return _doc_to_response(doc)


@router.post("/documents/{doc_id}/analyze")
async def analyze_document(
    doc_id: int,
    current_user: User = Depends(require_role(*ANALYZE_ROLES)),
):
    # Use a fresh session for initial read, then close it before the long Ollama call
    db = SessionLocal()
    try:
        doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")

        # Extract text
        text = _extract_text(doc.file_data, doc.file_type, doc.file_name)
        # Close session before long Ollama call (MySQL timeout)
        db.close()
    except HTTPException:
        db.close()
        raise
    except Exception:
        db.close()
        raise

    # Call Ollama (can take >30s)
    try:
        analysis = await _ollama_analyze(text)
    except Exception as e:
        logger.error("Ollama analysis failed: %s", e)
        raise HTTPException(status_code=502, detail=f"AI analysis failed: {e}")

    # Fresh session to save analysis
    db2 = SessionLocal()
    try:
        doc2 = db2.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
        if not doc2:
            raise HTTPException(status_code=404, detail="Document not found")
        doc2.ai_analysis = analysis
        doc2.ai_analyzed_at = datetime.now(timezone.utc)
        doc2.updated_at = datetime.now(timezone.utc)
        db2.commit()
        db2.refresh(doc2)
        # Audit: analyzed
        _audit_doc_action(db2, doc_id, "analyzed", current_user, details=f"Model: {cfg_get('ollama.model', 'qwen3:4b')}, URL: {cfg_get('ollama.url', 'localhost')}, Temperature: {cfg_get('ollama.temperature', '0.1')}, Pages/req: {cfg_get('ollama.pages_per_request', '1')}")
        return _doc_to_response(doc2)
    finally:
        db2.close()


@router.get("/documents/{doc_id}/analysis")
def get_analysis(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return {
        "id": doc.id,
        "ai_analysis": doc.ai_analysis,
        "ai_analyzed_at": doc.ai_analyzed_at.isoformat() if doc.ai_analyzed_at else None,
    }


@router.get("/documents/{doc_id}/audit")
def get_document_audit(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get audit trail for a specific document (all authenticated roles)."""
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    entries = db.query(PolicyDocumentAudit).filter(
        PolicyDocumentAudit.document_id == doc_id
    ).order_by(PolicyDocumentAudit.timestamp.desc()).all()

    return [{
        "id": e.id,
        "document_id": e.document_id,
        "action_type": e.action_type,
        "user_id": e.user_id,
        "username": e.username,
        "details": e.details,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
    } for e in entries]


@router.get("/audit")
def list_audit(
    document_id: Optional[int] = Query(None),
    action_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "rssi")),
):
    """Global audit trail (admin/rssi only) with optional filters."""
    q = db.query(PolicyDocumentAudit)

    if document_id:
        q = q.filter(PolicyDocumentAudit.document_id == document_id)
    if action_type:
        q = q.filter(PolicyDocumentAudit.action_type == action_type)

    entries = q.order_by(PolicyDocumentAudit.timestamp.desc()).limit(limit).all()

    # Join with document names for context
    doc_ids = [e.document_id for e in entries]
    docs_map = {}
    if doc_ids:
        docs = db.query(PolicyDocument).filter(PolicyDocument.id.in_(doc_ids)).all()
        docs_map = {d.id: d.name for d in docs}

    return [{
        "id": e.id,
        "document_id": e.document_id,
        "document_name": docs_map.get(e.document_id, "(deleted)"),
        "action_type": e.action_type,
        "user_id": e.user_id,
        "username": e.username,
        "details": e.details,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
    } for e in entries]


# ── ANSSI referentials for policy wizard ──

ANSSI_STEPS = {
    "pssi": [
        {"step": 1, "title": "Domaine d'application et perimetre", "description": "Definir le perimetre de la PSSI : systemes, reseaux, sites, personnes concernees."},
        {"step": 2, "title": "Objectifs de securite alignes avec la strategie", "description": "Formuler les objectifs de securite en lien avec la strategie de l'organisation (confidentialite, integrite, disponibilite)."},
        {"step": 3, "title": "Organisation de la gouvernance", "description": "Decrire les roles et responsabilites : RSSI, DSI, direction, referents securite."},
        {"step": 4, "title": "Gestion des risques (reference EBIOS RM)", "description": "Identifier, analyser et traiter les risques selon la methode EBIOS RM de l'ANSSI."},
        {"step": 5, "title": "Regles de securite par domaine", "description": "Definir les regles pour le reseau, les systemes, les donnees, les acces logiques et physiques."},
        {"step": 6, "title": "Gestion des incidents et continuite", "description": "Decrire le processus de gestion des incidents de securite et le plan de continuite d'activite."},
        {"step": 7, "title": "Revision et validation", "description": "Preciser les modalites de revision, de validation et de mise a jour de la PSSI."},
    ],
    "charter": [
        {"step": 1, "title": "Objet et perimetre", "description": "Definir l'objet de la charte et son perimetre d'application."},
        {"step": 2, "title": "Engagements de l'organisation", "description": "Lister les engagements de l'organisme envers les utilisateurs (moyens mis a disposition, regles de bon usage)."},
        {"step": 3, "title": "Regles d'utilisation", "description": "Preciser les regles d'utilisation du materiel, des reseaux et de la messagerie."},
        {"step": 4, "title": "Regles specifiques", "description": "Aborder les points specifiques : BYOD, Cloud, IA generative, Shadow IT."},
        {"step": 5, "title": "Sanctions et validation", "description": "Definir les sanctions en cas de non-respect et les modalites de validation de la charte."},
    ],
    "data_gov": [
        {"step": 1, "title": "Classification des donnees", "description": "Etablir une echelle de classification : publique, interne, confidentiel, secret."},
        {"step": 2, "title": "Regles RGPD et droits des personnes", "description": "Integrer les obligations RGPD : consentement, droit d'acces, droit a l'oubli, DPO."},
        {"step": 3, "title": "Cycle de vie des donnees", "description": "Decrire le cycle de vie : creation, stockage, archivage, destruction."},
        {"step": 4, "title": "Responsabilites des Data Owners", "description": "Nommer les Data Owners et definir leurs responsabilites."},
        {"step": 5, "title": "Regles de retention et archivage legal", "description": "Fixer les durees de conservation conformement aux obligations legales."},
        {"step": 6, "title": "Anonymisation et chiffrement", "description": "Decrire les mesures techniques : anonymisation, pseudonymisation, chiffrement au repos et en transit."},
    ],
    "backup": [
        {"step": 1, "title": "Perimetre des sauvegardes", "description": "Identifier les systemes et donnees a sauvegarder."},
        {"step": 2, "title": "Strategie technique", "description": "Definir la strategie : immuabilite, air-gapped, externalisation."},
        {"step": 3, "title": "Definition RPO/RTO par service", "description": "Fixer les RPO et RTO pour chaque service critique."},
        {"step": 4, "title": "Tests de restauration et frequence", "description": "Planifier les tests de restauration et leur frequence."},
        {"step": 5, "title": "Integration avec le PCA/PCS", "description": "Integrer les sauvegardes dans le Plan de Continuite d'Activite et le Plan de Continuite de Service."},
    ],
    "iam": [
        {"step": 1, "title": "Principe du moindre privilege", "description": "Poser le principe du moindre privilege comme fondement de la politique IAM."},
        {"step": 2, "title": "Processus onboarding/offboarding", "description": "Decrire les processus de creation, modification et suppression des acces."},
        {"step": 3, "title": "Politique de mots de passe et MFA", "description": "Definir les regles de mots de passe et l'authentification multifacteur."},
        {"step": 4, "title": "Gestion des comptes a privileges", "description": "Organiser la gestion des comptes administrateurs et comptes de service."},
        {"step": 5, "title": "Revue periodique des acces", "description": "Mettre en place des revues periodiques des droits d'acces."},
        {"step": 6, "title": "Acces tiers et prestataires", "description": "Regir les acces des prestataires et sous-traitants."},
    ],
}

VALID_WIZARD_CATEGORIES = set(ANSSI_STEPS.keys())


class WizardCompanyInfo(BaseModel):
    name: str
    size: str  # TPE, PME, ETI, grande entreprise
    sector: str  # Sante, Finance, Industrie, Public, Services, Autre
    sites: int = 1
    systems: str = ""
    compliance: list[str] = []
    maturity: str = "intermediaire"  # debutant, intermediaire, avance


class WizardGenerateRequest(BaseModel):
    category: str
    step: int
    company_info: WizardCompanyInfo
    current_content: str = ""
    previous_steps: list[dict] = []


class WizardStepInfo(BaseModel):
    step: int
    title: str
    content: str


class WizardFinalizeRequest(BaseModel):
    category: str
    name: str
    company_info: WizardCompanyInfo
    steps: list[WizardStepInfo]
    generated_by_ia: bool = False


def _build_prompt(category: str, step: int, company_info: WizardCompanyInfo, current_content: str, previous_steps: list[dict]) -> str:
    """Build the AI prompt for a given wizard step."""
    from app.routers.ia_prompts import get_prompt as _get_prompt

    steps_def = ANSSI_STEPS.get(category, [])
    step_info = None
    for s in steps_def:
        if s["step"] == step:
            step_info = s
            break
    if not step_info:
        step_info = {"title": f"Etape {step}", "description": "Contenu de cette etape."}

    compliance_str = ", ".join(company_info.compliance) if company_info.compliance else "Aucune specifiee"

    prompt_template = _get_prompt("wizard_generate")

    # Build variable substitutions
    previous_steps_section = ""
    if previous_steps:
        previous_steps_section = "Sections precedemment redigees :\n"
        for ps in previous_steps:
            previous_steps_section += f"- Etape {ps.get('step', '?')}: {ps.get('title', '')}\n"
            content_preview = str(ps.get('content', ''))[:500]
            previous_steps_section += f"  {content_preview}\n"

    current_content_section = ""
    if current_content:
        current_content_section = (
            f"Voici le brouillon actuel pour cette etape :\n{current_content}\n\n"
            f"Ameliore et enrichis ce brouillon en ajoutant des precisions, des bonnes pratiques "
            f"et en alignant avec le referentiel ANSSI. Garde le contenu structure et professionnel.\n"
        )
    else:
        current_content_section = (
            "Redige le contenu de cette section de maniere professionnelle et structuree. "
            "Base-toi sur le referentiel ANSSI, les bonnes pratiques du secteur et les contraintes "
            "reglementaires mentionnees. Le texte doit etre directement utilisable dans le document final.\n"
        )

    prompt = prompt_template \
        .replace("{category}", category.upper()) \
        .replace("{step}", str(step)) \
        .replace("{step_title}", step_info['title']) \
        .replace("{step_description}", step_info['description']) \
        .replace("{company_info_name}", company_info.name) \
        .replace("{company_info_size}", company_info.size) \
        .replace("{company_info_sector}", company_info.sector) \
        .replace("{company_info_sites}", str(company_info.sites)) \
        .replace("{company_info_systems}", company_info.systems or "Non specifie") \
        .replace("{company_info_compliance}", compliance_str) \
        .replace("{company_info_maturity}", company_info.maturity) \
        .replace("{previous_steps_section}", previous_steps_section) \
        .replace("{current_content_section}", current_content_section)

    return prompt


@router.post("/generate")
async def wizard_generate(
    body: WizardGenerateRequest,
    current_user: User = Depends(require_role(*EDIT_ROLES)),
    db: Session = Depends(get_db),
):
    """Generate or improve content for a policy wizard step using AI."""
    if body.category not in VALID_WIZARD_CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Invalid category. Must be one of: {', '.join(sorted(VALID_WIZARD_CATEGORIES))}")

    steps_def = ANSSI_STEPS[body.category]
    step_numbers = [s["step"] for s in steps_def]
    if body.step not in step_numbers:
        raise HTTPException(status_code=400, detail=f"Invalid step for category {body.category}. Valid steps: {step_numbers}")

    prompt = _build_prompt(body.category, body.step, body.company_info, body.current_content, body.previous_steps)

    ollama_url = cfg_get("ollama.url", "http://127.0.0.1:11434")
    ollama_model = cfg_get("ollama.model", "qwen3:4b")
    ollama_timeout = max(int(cfg_get("ollama.timeout", "30")), 120)

    # Close DB session before slow Ollama call to avoid MySQL timeout
    db.close()

    payload = {
        "model": ollama_model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
            "think": _think_param(),
        "options": {"num_predict": 4096, "temperature": float(cfg_get("ollama.temperature", "0.1")), "num_ctx": int(cfg_get("ollama.context_length", "4096"))},
    }

    try:
        async with httpx.AsyncClient(timeout=float(ollama_timeout + 10)) as client:
            resp = await client.post(f"{ollama_url.rstrip('/')}/api/chat", json=payload, headers={"Authorization": f"Bearer {cfg_get('ollama.api_key', '')}"} if cfg_get("ollama.api_key", "") else {})
            resp.raise_for_status()
            data = resp.json()
            generated = data.get("message", {}).get("content", "") or data.get("response", "")
    except Exception as e:
        logger.error("Ollama wizard generate failed: %s", repr(e))
        raise HTTPException(status_code=502, detail=f"AI generation failed: {e}")

    # Build suggestions based on step
    suggestions_map = {
        "pssi": "Pensez a aligner vos objectifs avec la norme ISO 27001 et la methode EBIOS RM pour l'analyse des risques.",
        "charter": "Assurez-vous que la charte est signee par chaque collaborateur et revisee annuellement.",
        "data_gov": "Verifiez la conformite avec le RGPD et identifiez les traitements necessitant une AIPD.",
        "backup": "Pensez a tester regulierement la restauration et a conserver des sauvegardes immmuables hors site.",
        "iam": "Mettez en place une revue trimestrielle des acces privilegies et activez l'authentification multifacteur.",
    }
    suggestions = suggestions_map.get(body.category, "")

    return {
        "generated_content": generated,
        "suggestions": suggestions,
        "model": ollama_model,
    }


@router.get("/wizard/steps")
def wizard_steps(
    category: str = Query(..., description="Policy category: pssi, charter, data_gov, backup, iam"),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Return the step definitions for a policy category."""
    if category not in VALID_WIZARD_CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Invalid category. Must be one of: {', '.join(sorted(VALID_WIZARD_CATEGORIES))}")
    return ANSSI_STEPS[category]


@router.post("/wizard/finalize")
async def wizard_finalize(
    body: WizardFinalizeRequest,
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Compile all wizard steps into a policy document and save it."""
    if body.category not in VALID_WIZARD_CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Invalid category. Must be one of: {', '.join(sorted(VALID_WIZARD_CATEGORIES))}")

    # Build document text from steps
    lines = [
        f"# {body.name}",
        f"",
        f"Type : {body.category.upper()}",
        f"Organisation : {body.company_info.name}",
        f"Taille : {body.company_info.size}",
        f"Secteur : {body.company_info.sector}",
        f"Sites : {body.company_info.sites}",
        f"Systemes : {body.company_info.systems or 'Non specifie'}",
        f"Conformite : {', '.join(body.company_info.compliance) if body.company_info.compliance else 'Non specifie'}",
        f"Maturite : {body.company_info.maturity}",
        f"",
        "---",
        "",
    ]

    for step in body.steps:
        lines.append(f"## Etape {step.step} : {step.title}")
        lines.append("")
        lines.append(step.content)
        lines.append("")

    document_text = "\n".join(lines)

    # Optionally send to Ollama for a final review (best-effort, don't block on failure)
    final_text = document_text
    try:
        from app.routers.ia_prompts import get_prompt as _get_prompt

        ollama_url = cfg_get("ollama.url", "http://127.0.0.1:11434")
        ollama_model = cfg_get("ollama.model", "qwen3:4b")
        ollama_timeout = max(int(cfg_get("ollama.timeout", "30")), 120)

        prompt_template = _get_prompt("wizard_finalize")
        review_prompt = prompt_template.replace("{content}", document_text[:8000])
        payload = {
            "model": ollama_model,
            "messages": [{"role": "user", "content": review_prompt}],
            "stream": False,
            "think": _think_param(),
            "options": {"num_predict": 8192, "temperature": float(cfg_get("ollama.temperature", "0.1")), "num_ctx": int(cfg_get("ollama.context_length", "4096"))},
        }
        async with httpx.AsyncClient(timeout=float(ollama_timeout + 10)) as client:
            resp = await client.post(f"{ollama_url.rstrip('/')}/api/chat", json=payload, headers={"Authorization": f"Bearer {cfg_get('ollama.api_key', '')}"} if cfg_get("ollama.api_key", "") else {})
            resp.raise_for_status()
            data = resp.json()
            reviewed = data.get("message", {}).get("content", "") or data.get("response", "")
            if reviewed.strip():
                final_text = reviewed
    except Exception as e:
        logger.warning("Ollama final review failed, using raw text: %s", e)

    # Save as policy document (TXT in file_data)
    file_data = final_text.encode("utf-8")
    # Determine version string
    version_str = "V-01-IA" if body.generated_by_ia else "V-01"
    doc = PolicyDocument(
        name=body.name,
        category=body.category,
        version=version_str,
        status="draft",
        description=f"Document genere par l'assistant IA ({body.category})",
        file_data=file_data,
        file_name=f"{body.name.replace(' ', '_')}.txt",
        file_type="text/plain",
        file_size=len(file_data),
        created_by=current_user.id,
        revision=1,
        review_status="pending_review",
        generated_by_ia=body.generated_by_ia,
    )
    db = SessionLocal()
    try:
        db.add(doc)
        db.commit()
        db.refresh(doc)
        # Audit: imported
        _audit_doc_action(db, doc.id, "imported", current_user, details=f"Document genere par l'assistant IA ({body.category})")
        return _doc_to_response(doc)
    finally:
        db.close()


# ── Review workflow endpoints ──

DSI_ROLES = ("admin", "rssi")
DIRECTION_ROLES = ("admin",)

@router.put("/documents/{doc_id}/review/dsi")
def review_dsi(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*DSI_ROLES)),
):
    """Mark document as reviewed by DSI."""
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.review_status not in ("pending_review", "reviewed_dsi"):
        raise HTTPException(status_code=400, detail=f"Document review status is '{doc.review_status}', cannot validate DSI")
    doc.reviewed_by_dsi = current_user.id
    doc.reviewed_dsi_at = datetime.now(timezone.utc)
    doc.review_status = "reviewed_dsi"
    doc.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(doc)
    _audit_doc_action(db, doc_id, "reviewed_dsi", current_user)
    return _doc_to_response(doc)


@router.put("/documents/{doc_id}/review/direction")
def review_direction(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*DIRECTION_ROLES)),
):
    """Mark document as reviewed by Direction (final approval)."""
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.review_status not in ("reviewed_dsi", "approved"):
        raise HTTPException(status_code=400, detail=f"Document review status is '{doc.review_status}', must be 'reviewed_dsi' before Direction approval")
    doc.reviewed_by_direction = current_user.id
    doc.reviewed_direction_at = datetime.now(timezone.utc)
    doc.review_status = "approved"
    doc.status = "approved"
    doc.approved_by = current_user.id
    doc.approved_at = datetime.now(timezone.utc)
    doc.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(doc)
    _audit_doc_action(db, doc_id, "reviewed_direction", current_user)
    return _doc_to_response(doc)


# ── Page-by-page analysis for reference documents ──

def _enqueue_analysis(doc_id: int, total_pages: int, file_data: bytes, file_type: str, file_name: str):
    """Add analysis to queue. The queue processor must be started separately."""
    _analysis_queue.append((doc_id, total_pages, file_data, file_type, file_name))
    logger.info("Analysis enqueued for doc %d (%d pages). Queue size: %d", doc_id, total_pages, len(_analysis_queue))


async def _start_queue_processor():
    """Start the queue processor as an asyncio task. Must be called from an async context.
    Uses _analysis_thread_lock to be consistent with _run_queue_processor_sync."""
    global _analysis_running, _analysis_processor_task
    logger.warning("START_QUEUE_PROCESSOR called. running=%s queue=%d", _analysis_running, len(_analysis_queue))
    with _analysis_thread_lock:
        if _analysis_running:
            logger.warning("Queue processor already running. Queue size: %d", len(_analysis_queue))
            return
        if not _analysis_queue:
            logger.warning("Queue empty, nothing to process")
            return
        _analysis_running = True
    # Store the task reference so it's not garbage collected
    _analysis_processor_task = _asyncio_mod.ensure_future(_process_analysis_queue())
    logger.warning("Queue processor started (async). Queue size: %d", len(_analysis_queue))


async def _recover_pending_analyses_async():
    """Re-enqueue analyses that were interrupted by a container restart.
    Called from an async endpoint. Finds docs with pages in 'pending' or 'analyzing' status
    and re-enqueues them.
    """
    db = SessionLocal()
    try:
        pending_docs = db.query(PolicyDocumentPage.document_id).filter(
            PolicyDocumentPage.status.in_(["pending", "analyzing"])
        ).distinct().all()

        for (doc_id,) in pending_docs:
            # Skip if already in queue
            if any(qid == doc_id for (qid, _, _, _, _) in _analysis_queue):
                continue
            doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
            if not doc or not doc.file_data:
                continue
            # Skip documents marked as skip_analysis
            if doc.skip_analysis:
                continue

            analyzing_pages = db.query(PolicyDocumentPage).filter(
                PolicyDocumentPage.document_id == doc_id,
                PolicyDocumentPage.status == "analyzing"
            ).all()
            for p in analyzing_pages:
                p.status = "pending"
            db.commit()

            total = db.query(PolicyDocumentPage).filter(
                PolicyDocumentPage.document_id == doc_id
            ).count()

            _analysis_queue.append((doc_id, total, bytes(doc.file_data), doc.file_type or "", doc.file_name or ""))
            logger.info("Recovered pending analysis for doc %d (%d pages)", doc_id, total)

    except Exception as e:
        logger.error("Failed to recover pending analyses: %s", repr(e))
    finally:
        db.close()

    # Start queue processor
    if _analysis_queue:
        global _analysis_processor_task
        _analysis_processor_task = _asyncio_mod.ensure_future(_process_analysis_queue_safe())


def _run_queue_processor_sync():
    """Sync wrapper to run the async queue processor in a background task.
    Uses a threading lock + _analysis_running flag to ensure only ONE processor
    thread runs at a time. If a processor is already running, this is a no-op —
    the running processor will pick up the queued item."""
    global _analysis_running
    with _analysis_thread_lock:
        if _analysis_running:
            logger.info("Queue processor already running. Item will be picked up. Queue size: %d", len(_analysis_queue))
            return
        _analysis_running = True
    try:
        loop = _asyncio_mod.new_event_loop()
        _asyncio_mod.set_event_loop(loop)
        loop.run_until_complete(_process_analysis_queue())
    except Exception as e:
        logger.error("Queue processor failed: %s", repr(e))
    finally:
        with _analysis_thread_lock:
            _analysis_running = False
        loop.close()


_analysis_processor_task = None  # keep ref so GC doesn't cancel the task


async def _process_analysis_queue_safe():
    """Wrapper that ensures _analysis_running is always reset, even on crash."""
    global _analysis_running, _analysis_processor_task
    if _analysis_running:
        # Check if the processor is actually doing something
        # If no pages are "analyzing", the flag is stuck — reset it
        try:
            db = SessionLocal()
            stuck = db.query(PolicyDocumentPage).filter(PolicyDocumentPage.status == "analyzing").count()
            db.close()
            if stuck == 0:
                logger.warning("Flag stuck at True but no pages analyzing — resetting")
                _analysis_running = False
            else:
                logger.warning("SKIP: processor already running, %d pages analyzing", stuck)
                return
        except Exception:
            pass
    _analysis_running = True
    try:
        await _process_analysis_queue()
    except Exception as e:
        logger.error("Queue processor crashed: %s", repr(e))
    finally:
        _analysis_running = False
        _analysis_processor_task = None
        logger.warning("Queue processor finished. running reset to False.")


async def _process_analysis_queue():
    """Process analysis queue one at a time."""
    while _analysis_queue:
        doc_id, total_pages, file_data, file_type, file_name = _analysis_queue.pop(0)
        logger.warning("Starting queued analysis for doc %d (%d pages). Remaining: %d", doc_id, total_pages, len(_analysis_queue))
        try:
            await _analyze_pages_background(doc_id, total_pages, file_data, file_type, file_name)
        except Exception as e:
            logger.error("Queued analysis failed for doc %d: %s", doc_id, repr(e))
    logger.warning("Analysis queue empty.")


def _get_deliverables_list_for_prompt(db) -> str:
    """Return a formatted list of governance deliverables for the IA prompt.
    Lists all deliverables (active or not) grouped by regulatory_framework."""
    from app.models import GovernanceDeliverable
    rows = db.query(GovernanceDeliverable).order_by(
        GovernanceDeliverable.regulatory_framework, GovernanceDeliverable.id
    ).all()
    if not rows:
        return '   - Aucun livrable defini (inscrire "N/A")'
    lines = []
    current_fw = None
    for r in rows:
        if r.regulatory_framework != current_fw:
            current_fw = r.regulatory_framework
            lines.append(f'   [{current_fw}]')
        lines.append(f'   - {r.id} = {r.deliverable_name} ({r.driver})')
    return chr(10).join(lines)


DELIVERABLE_TYPES_LIST = [
    ("Document_Cadre", "documents de politique et de strategie de securite SI (PSSI, charte SI, directives, regles d acces, politique de mots de passe, politique de chiffrement)"),
    ("Configuration_Securite", "durcissement et parametrage technique d un equipement, OS, application ou reseau (PAM, SSH, GPO, firewall, BitLocker, durcissement AD/Windows/Linux, securite container, securite DB)"),
    ("Rapport_Audit", "rapports de controle, d audit, de verification ou d analyse (audit annuel, pentest, analyse de risques EBIOS RM, bilan de conformite, rapport d incident majeur)"),
    ("Tache_Operationnelle", "taches recurrentes d exploitation, de maintenance ou de surveillance (sauvegardes, monitoring des logs, application des correctifs, rotation des mots de passe, tests de restauration, renouvellement des certificats)"),
    ("Registre_Inventaire", "tenue de registres, d inventaires ou de cartographies a jour en continu (registre des traitements RGPD, inventaire des assets SI, registre des incidents, cartographie des flux, registre des acces privilegies)"),
    ("Charte_Contrat", "documents d engagement, de responsabilisation ou de contractualisation entre parties (charte utilisateur, NDA, clauses de securite fournisseurs, SLA, charte administrateur)"),
]


def _get_deliverable_types_list_for_prompt() -> str:
    lines = []
    for name, desc in DELIVERABLE_TYPES_LIST:
        lines.append("   - " + name + " : " + desc)
    return chr(10).join(lines)


async def _analyze_pages_background(doc_id: int, total_pages: int, file_data: bytes, file_type: str, file_name: str):
    """Background task: analyze each page of a PDF document with Ollama."""
    from app.routers.ia_prompts import get_prompt as _get_prompt

    ollama_url = cfg_get("ollama.url", "http://127.0.0.1:11434")
    ollama_model = cfg_get("ollama.model", "qwen3:4b")
    ollama_timeout_raw = int(cfg_get("ollama.timeout", "30"))
    # Per-page timeout: max(ollama_timeout, 60) + 10
    per_page_timeout = max(ollama_timeout_raw, 60) + 10

    prompt_template = _get_prompt("reference_page_analysis")

    # Inject deliverables list into prompt
    _db_dl = SessionLocal()
    try:
        _deliverables_list = _get_deliverables_list_for_prompt(_db_dl)
    finally:
        _db_dl.close()
    if "{deliverables_list}" in prompt_template:
        prompt_template = prompt_template.replace("{deliverables_list}", _deliverables_list)

    # Inject deliverable_types list (6 categories) into prompt
    _deliverable_types_list = _get_deliverable_types_list_for_prompt()
    if "{deliverable_types_list}" in prompt_template:
        prompt_template = prompt_template.replace("{deliverable_types_list}", _deliverable_types_list)

    # Inject framework and document_type into prompt (from document_pre_analysis)
    _fw = _get_doc_regulatory_framework(_db_dl, doc_id)
    if "{framework}" in prompt_template:
        prompt_template = prompt_template.replace("{framework}", _fw)
    _pa = _db_dl.query(DocumentPreAnalysis).filter(DocumentPreAnalysis.document_id == doc_id).first()
    _doc_type = _pa.document_type if _pa and _pa.document_type else "Guide technique"
    if "{document_type}" in prompt_template:
        prompt_template = prompt_template.replace("{document_type}", _doc_type)

    # Audit: log model and URL used for this analysis
    _ollama_url_logged = cfg_get("ollama.url", "localhost")
    _ollama_model_logged = cfg_get("ollama.model", "qwen3:4b")
    _ollama_temp_logged = cfg_get("ollama.temperature", "0.1")
    _ollama_pages_logged = cfg_get("ollama.pages_per_request", "1")
    _ollama_ctx_logged = cfg_get("ollama.context_length", "4096")
    logger.info("Analysis started for doc %d with model=%s url=%s temp=%s pages_per_req=%s ctx=%s",
                doc_id, _ollama_model_logged, _ollama_url_logged, _ollama_temp_logged, _ollama_pages_logged, _ollama_ctx_logged)

    # Extract pages using PyPDF2
    try:
        from PyPDF2 import PdfReader
        reader = PdfReader(io.BytesIO(file_data))
        pages_text = []
        for page in reader.pages:
            text = page.extract_text()
            pages_text.append(text or "")
    except Exception as e:
        logger.error("Failed to extract PDF pages for doc %d: %s", doc_id, e)
        # Mark all pages as error
        db_err = SessionLocal()
        try:
            for pn in range(1, total_pages + 1):
                page_row = db_err.query(PolicyDocumentPage).filter(
                    PolicyDocumentPage.document_id == doc_id,
                    PolicyDocumentPage.page_number == pn
                ).first()
                if page_row:
                    page_row.status = "error"
                    page_row.error_message = f"PDF extraction failed: {e}"
                    page_row.updated_at = datetime.now(timezone.utc)
            db_err.commit()
        finally:
            db_err.close()
        return

    # Read pages_per_request config
    pages_per_request = int(cfg_get("ollama.pages_per_request", "1"))
    if pages_per_request < 1:
        pages_per_request = 1

    # Process pages in batches
    page_num = 1
    while page_num <= total_pages:
        # Check if analysis was stopped
        if _analysis_stop_flags.get(doc_id):
            db_stop = SessionLocal()
            try:
                # Remettre les pages restantes en pending (pas skipped) pour reprise future
                remaining = db_stop.query(PolicyDocumentPage).filter(
                    PolicyDocumentPage.document_id == doc_id,
                    PolicyDocumentPage.status.in_(["pending", "analyzing"])
                ).all()
                for r in remaining:
                    r.status = "pending"
                db_stop.commit()
            finally:
                db_stop.close()
            _analysis_stop_flags.pop(doc_id, None)
            logger.info("Analysis stopped for doc %d at page %d/%d", doc_id, page_num - 1, total_pages)
            return

        # Determine batch range
        batch_end = min(page_num + pages_per_request - 1, total_pages)
        batch_pages = list(range(page_num, batch_end + 1))

        # Collect texts for this batch
        batch_texts = []
        batch_page_nums = []
        db_batch = SessionLocal()
        try:
            for pn in batch_pages:
                text = pages_text[pn - 1] if pn <= len(pages_text) else ""
                if not text or len(text.strip()) < 50:
                    page_row = db_batch.query(PolicyDocumentPage).filter(
                        PolicyDocumentPage.document_id == doc_id,
                        PolicyDocumentPage.page_number == pn
                    ).first()
                    if page_row:
                        page_row.status = "skipped"
                        page_row.result_text = "RIEN"
                        page_row.updated_at = datetime.now(timezone.utc)
                    continue
                batch_texts.append(text)
                batch_page_nums.append(pn)
            db_batch.commit()

            if not batch_texts:
                page_num = batch_end + 1
                continue

            # Mark all batch pages as analyzing
            for pn in batch_page_nums:
                pr = db_batch.query(PolicyDocumentPage).filter(
                    PolicyDocumentPage.document_id == doc_id,
                    PolicyDocumentPage.page_number == pn
                ).first()
                if pr:
                    pr.status = "analyzing"
                    pr.updated_at = datetime.now(timezone.utc)
            db_batch.commit()
        finally:
            db_batch.close()

        # Build prompt
        if pages_per_request == 1:
            prompt = prompt_template.replace("{text}", batch_texts[0][:8000])
        else:
            pages_content = ""
            for i, (pn, txt) in enumerate(zip(batch_page_nums, batch_texts)):
                pages_content += f"--- Page {pn} ---\n{txt[:4000]}\n\n"
            prompt = prompt_template.replace("{text}", pages_content)

        payload = {
            "model": ollama_model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "think": _think_param(),
            "options": {"num_predict": 8192, "temperature": float(cfg_get("ollama.temperature", "0.1")), "num_ctx": int(cfg_get("ollama.context_length", "4096"))},
        }

        # Timeout for Ollama Cloud (kimi-k2.6) — 5 min per batch to avoid ReadTimeout
        batch_timeout = max(float(per_page_timeout * max(1, len(batch_page_nums) // 2 + 1)), 300.0)

        db_result = SessionLocal()
        try:
            # Retry logic: 3 attempts per page batch
            max_retries = 3
            retry_delay = 5  # seconds between retries
            success = False
            last_error = None

            for attempt in range(1, max_retries + 1):
                try:
                    async with httpx.AsyncClient(timeout=batch_timeout) as client:
                        resp = await client.post(f"{ollama_url.rstrip('/')}/api/chat", json=payload, headers={"Authorization": f"Bearer {cfg_get('ollama.api_key', '')}"} if cfg_get("ollama.api_key", "") else {})
                        resp.raise_for_status()
                        data = resp.json()
                        result = (data.get("message", {}).get("content", "") or data.get("response", "") or "No response from AI").strip()
                    success = True
                    break
                except Exception as e:
                    last_error = e
                    error_str = repr(e)
                    logger.warning("Attempt %d/%d failed for doc %d pages %s: %s", attempt, max_retries, doc_id, batch_page_nums, error_str)

                    # 429 rate limit — stop immediately, no retry
                    if "429" in error_str or "Too Many Requests" in error_str:
                        logger.warning("Rate limit (429) detected for doc %d — stopping analysis immediately.", doc_id)
                        break

                    if attempt < max_retries:
                        import asyncio as _asyncio
                        await _asyncio.sleep(retry_delay * attempt)

            if not success:
                error_str = repr(last_error)
                is_rate_limited = "429" in error_str or "Too Many Requests" in error_str

                # Mark current batch pages as error
                for pn in batch_page_nums:
                    pr = db_result.query(PolicyDocumentPage).filter(
                        PolicyDocumentPage.document_id == doc_id,
                        PolicyDocumentPage.page_number == pn
                    ).first()
                    if pr:
                        pr.status = "error"
                        pr.error_message = error_str[:500]
                        pr.updated_at = datetime.now(timezone.utc)
                db_result.commit()

                if is_rate_limited:
                    # 429: mark ALL remaining pending pages as error and stop
                    logger.warning("Rate limit (429) — marking all remaining pages as error for doc %d.", doc_id)
                    remaining_pages = db_result.query(PolicyDocumentPage).filter(
                        PolicyDocumentPage.document_id == doc_id,
                        PolicyDocumentPage.status == "pending"
                    ).all()
                    for rp in remaining_pages:
                        rp.status = "error"
                        rp.error_message = "Rate limit (429) — analysis stopped"
                        rp.updated_at = datetime.now(timezone.utc)
                    db_result.commit()
                    db_result.close()
                    break
                else:
                    # Other error after 3 retries — stop document analysis too
                    logger.error("Doc %d failed after %d retries — stopping analysis.", doc_id, max_retries)
                    remaining_pages = db_result.query(PolicyDocumentPage).filter(
                        PolicyDocumentPage.document_id == doc_id,
                        PolicyDocumentPage.status == "pending"
                    ).all()
                    for rp in remaining_pages:
                        rp.status = "error"
                        rp.error_message = f"Failed after {max_retries} retries: {error_str[:400]}"
                        rp.updated_at = datetime.now(timezone.utc)
                    db_result.commit()
                    db_result.close()
                    break
            else:
                # Success — save results
                if result.upper().strip() == "RIEN" or result.strip() == "":
                    for pn in batch_page_nums:
                        pr = db_result.query(PolicyDocumentPage).filter(
                            PolicyDocumentPage.document_id == doc_id,
                            PolicyDocumentPage.page_number == pn
                        ).first()
                        if pr:
                            pr.status = "skipped"
                            pr.result_text = "RIEN"
                            pr.updated_at = datetime.now(timezone.utc)
                else:
                    for i, pn in enumerate(batch_page_nums):
                        pr = db_result.query(PolicyDocumentPage).filter(
                            PolicyDocumentPage.document_id == doc_id,
                            PolicyDocumentPage.page_number == pn
                        ).first()
                        if pr:
                            if pages_per_request == 1:
                                pr.status = "done"
                                pr.result_text = result
                            else:
                                if i == 0:
                                    pr.status = "done"
                                    pr.result_text = result
                                else:
                                    pr.status = "done"
                                    pr.result_text = f"(voir page {batch_page_nums[0]})"
                            pr.updated_at = datetime.now(timezone.utc)
                db_result.commit()
        finally:
            db_result.close()

        page_num = batch_end + 1

    # Compile final results into policy_documents.ai_analysis
    db_final = SessionLocal()
    try:
        doc = db_final.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
        if doc:
            done_pages = db_final.query(PolicyDocumentPage).filter(
                PolicyDocumentPage.document_id == doc_id,
                PolicyDocumentPage.status == "done"
            ).order_by(PolicyDocumentPage.page_number).all()

            # Compile into a single table
            table_header = "| ID / Référence | Règle / Exigence | Cible | Catégorie GRC | Livrable ID | Acteur Destinataire | Fréquence | Criticité |\n|---|---|---|---|---|---|---|---|\n"
            table_rows = []
            for p in done_pages:
                if not p.result_text:
                    continue
                # Extract table rows from the page result (skip headers)
                for line in p.result_text.split("\n"):
                    line = line.strip()
                    if line.startswith("|") and not line.startswith("| ID / Reference") and not line.startswith("| ID / Référence") and not line.startswith("|---") and not line.startswith("| ref_id") and not line.startswith("| entry_type"):
                        table_rows.append(line)

            if table_rows:
                doc.ai_analysis = table_header + "\n".join(table_rows)
                doc.ai_analysis += "\n\n---\n\n⚠️ Cette analyse a ete generee par une IA et ne se substitue pas a la lecture attentive du document original.\n"
            else:
                doc.ai_analysis = "Aucune exigence trouvee dans le document."
            doc.ai_analyzed_at = datetime.now(timezone.utc)
            doc.updated_at = datetime.now(timezone.utc)
            db_final.commit()

            # Auto-parse requirements after successful compilation
            _auto_parse_requirements(doc_id)
            # Post-process: fix misclassified requirements
            try:
                _post_process_requirements(doc_id)
            except Exception as e:
                logger.warning("Post-process requirements failed for doc %d: %s", doc_id, repr(e))
            # AI relink: link remaining requirements to deliverables via semantic matching
            try:
                _ai_relink_requirements(doc_id)
            except Exception as e:
                logger.warning("AI relink failed for doc %d: %s", doc_id, repr(e))
            # Target mapping: link requirements to CMDB assets via target_asset_mappings
            try:
                _link_requirements_to_assets(doc_id)
            except Exception as e:
                logger.warning("Target-mapping links failed for doc %d: %s", doc_id, repr(e))
            # Auto-associate new requirements to existing CMDB assets
            try:
                _auto_associate_requirements_to_assets(doc_id)
            except Exception as e:
                logger.warning("Auto-associate requirements to assets failed for doc %d: %s", doc_id, repr(e))
            # Auto-enrich domain skills with extracted requirements
            try:
                _auto_enrich_skills(doc_id)
            except Exception as e:
                logger.warning("Auto-enrich skills failed for doc %d: %s", doc_id, repr(e))
    except Exception as e:
        logger.error("Failed to compile final analysis for doc %d: %s", doc_id, e)
    finally:
        db_final.close()


def _auto_associate_requirements_to_assets(doc_id: int):
    """After parsing requirements from a document, auto-associate them to existing CMDB assets
    based on GRC rules. For each new requirement, find assets whose GRC fields match."""
    from app.models import AssetCmdb, AssetRequirementLink, AssetRequirementRule, ReferenceRequirement
    from app.routers.grc_bridge import _match_asset_value, _find_matching_requirements, _invalidate_score_cache, DEFAULT_RULES

    db = SessionLocal()
    try:
        # Get requirements from this document
        reqs = db.query(ReferenceRequirement).filter(
            ReferenceRequirement.document_id == doc_id
        ).all()
        if not reqs:
            return

        # Load rules (seed defaults if empty)
        rules = db.query(AssetRequirementRule).filter(AssetRequirementRule.auto_assign == True).all()
        if not rules:
            for rule_data in DEFAULT_RULES:
                rule = AssetRequirementRule(
                    name=rule_data["name"],
                    match_field=rule_data["match_field"],
                    match_operator=rule_data["match_operator"],
                    match_value=rule_data["match_value"],
                    requirement_filters=rule_data["requirement_filters"],
                    auto_assign=True,
                )
                db.add(rule)
            db.commit()
            rules = db.query(AssetRequirementRule).filter(AssetRequirementRule.auto_assign == True).all()

        # Get all assets
        assets = db.query(AssetCmdb).all()
        if not assets:
            return

        # For each rule, find which assets match and which requirements match
        total_created = 0
        for rule in rules:
            filters = rule.requirement_filters if isinstance(rule.requirement_filters, dict) else {}
            # Find requirements from this doc that match the rule filters
            matching_reqs = _find_matching_requirements(db, filters)
            doc_req_ids = set(r.id for r in reqs)
            rule_reqs = [r for r in matching_reqs if r.id in doc_req_ids]
            if not rule_reqs:
                continue

            # Find assets that match the rule
            matching_assets = [a for a in assets if _match_asset_value(a, rule.match_field, rule.match_operator, rule.match_value)]
            if not matching_assets:
                continue

            # Create links (avoid duplicates)
            for asset in matching_assets:
                existing = db.query(AssetRequirementLink).filter(
                    AssetRequirementLink.asset_id == asset.id,
                    AssetRequirementLink.requirement_id.in_([r.id for r in rule_reqs]),
                ).all()
                existing_req_ids = set(l.requirement_id for l in existing)

                for req in rule_reqs:
                    if req.id not in existing_req_ids:
                        link = AssetRequirementLink(
                            asset_id=asset.id,
                            requirement_id=req.id,
                            link_type="direct",
                            compliance_status="Non_traitee",
                        )
                        db.add(link)
                        existing_req_ids.add(req.id)
                        total_created += 1

                _invalidate_score_cache(asset.id)

        if total_created > 0:
            db.commit()
            logger.info("Auto-associated %d requirement-asset links for doc %d", total_created, doc_id)

    except Exception as e:
        logger.error("Auto-associate requirements to assets failed: %s", repr(e))
        db.rollback()
    finally:
        db.close()




def _auto_enrich_skills(doc_id: int):
    """Auto-enrich domain_skills after analysis completion.
    Called from _analyze_pages_background after _auto_parse_requirements.

    For each assistance skill matching the document's regulatory_framework:
    - Resolves skill deliverables_list (names) to deliverable IDs via governance_deliverables
    - If the skill covers a deliverable_id that has extracted requirements,
      append a structured summary of those requirements to the skill's system_prompt.
    - Idempotent: a marker [DOC-{doc_id}] replaces old block on re-enrichment.
    """
    from app.models import DomainSkill, ReferenceRequirement, PolicyDocument, GovernanceDeliverable

    db = SessionLocal()
    try:
        # Get the document's regulatory_framework
        doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
        if not doc:
            logger.warning("Auto-enrich: doc %d not found", doc_id)
            return
        framework = (doc.regulatory_framework or "ANSSI").upper().strip()

        # Get requirements for this doc, grouped by deliverable_id
        reqs = db.query(ReferenceRequirement).filter(
            ReferenceRequirement.document_id == doc_id
        ).all()
        if not reqs:
            logger.info("Auto-enrich: no requirements for doc %d, skipping", doc_id)
            return

        # Group requirements by deliverable_id
        by_deliverable = {}
        for r in reqs:
            did = r.deliverable_id
            if did is None:
                continue
            if did not in by_deliverable:
                by_deliverable[did] = []
            by_deliverable[did].append(r)

        if not by_deliverable:
            logger.info("Auto-enrich: no requirements with deliverable_id for doc %d, skipping", doc_id)
            return

        logger.info("Auto-enrich: doc %d framework=%s, %d deliverables with requirements: %s",
                     doc_id, framework, len(by_deliverable), sorted(by_deliverable.keys()))

        # Build a name->id map from governance_deliverables for this framework
        deliverable_rows = db.query(GovernanceDeliverable).filter(
            GovernanceDeliverable.regulatory_framework == framework
        ).all()
        name_to_id = {}
        for dr in deliverable_rows:
            name_to_id[dr.deliverable_name] = dr.id

        # Find assistance skills for this framework
        skills = db.query(DomainSkill).filter(
            DomainSkill.regulatory_framework == framework,
            DomainSkill.skill_type == "assistance",
        ).all()

        if not skills:
            logger.info("Auto-enrich: no assistance skills for framework %s, skipping", framework)
            return

        enriched_count = 0
        doc_marker = f"[DOC-{doc_id}]"
        import json as _json_enrich

        for skill in skills:
            # Parse deliverables_list (JSON array of deliverable NAMES)
            skill_deliverable_names = []
            if skill.deliverables_list:
                try:
                    dl = _json_enrich.loads(skill.deliverables_list)
                    if isinstance(dl, list):
                        skill_deliverable_names = dl
                except (ValueError, TypeError):
                    pass

            if not skill_deliverable_names:
                continue

            # Resolve names to IDs
            skill_deliverable_ids = set()
            for name in skill_deliverable_names:
                did = name_to_id.get(name)
                if did is not None:
                    skill_deliverable_ids.add(did)

            if not skill_deliverable_ids:
                logger.info("Auto-enrich: skill %d '%s' — no deliverable IDs resolved from names %s",
                            skill.id, skill.skill_name, skill_deliverable_names)
                continue

            # Find which deliverables from this doc match the skill
            matching_deliverables = skill_deliverable_ids.intersection(set(by_deliverable.keys()))
            if not matching_deliverables:
                continue

            # Build enrichment block
            enrichment_lines = [
                "",
                f"--- Enrichissement automatique {doc_marker} ---",
                f"Source: {doc.name} (framework={framework})",
                f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                "",
                "Exigences extraites pertinentes pour ce skill:",
            ]

            total_reqs = 0
            for did in sorted(matching_deliverables):
                req_list = by_deliverable[did]
                total_reqs += len(req_list)
                # Find the deliverable name
                deliv_name = "Unknown"
                for dr in deliverable_rows:
                    if dr.id == did:
                        deliv_name = dr.deliverable_name
                        break
                enrichment_lines.append("")
                enrichment_lines.append(f"## Livrable {did}: {deliv_name} ({len(req_list)} exigences)")
                for r in req_list[:50]:  # Cap at 50 reqs per deliverable
                    rule_short = (r.rule or "")[:200]
                    enrichment_lines.append(f"  - [{r.ref_id or 'N/A'}] {rule_short}")

            enrichment_lines.append(f"--- Fin enrichissement {doc_marker} ---")

            enrichment_block = chr(10).join(enrichment_lines)

            # Idempotent: remove old enrichment block for this doc if present
            current_prompt = skill.system_prompt or ""
            marker_start = f"--- Enrichissement automatique {doc_marker} ---"
            marker_end = f"--- Fin enrichissement {doc_marker} ---"

            if marker_start in current_prompt:
                idx_start = current_prompt.index(marker_start)
                if idx_start > 0 and current_prompt[idx_start - 1] == chr(10):
                    idx_start -= 1
                idx_end = current_prompt.find(marker_end, idx_start)
                if idx_end >= 0:
                    idx_end += len(marker_end)
                    if idx_end < len(current_prompt) and current_prompt[idx_end] == chr(10):
                        idx_end += 1
                    current_prompt = current_prompt[:idx_start] + current_prompt[idx_end:]

            # Append new enrichment block
            skill.system_prompt = current_prompt.rstrip() + chr(10) + enrichment_block
            skill.is_base = False
            skill.version += 1
            enriched_count += 1
            logger.info("Auto-enrich: skill %d '%s' enriched with %d requirements from %d deliverables (doc %d)",
                        skill.id, skill.skill_name, total_reqs, len(matching_deliverables), doc_id)

        if enriched_count > 0:
            db.commit()
            logger.info("Auto-enrich: enriched %d skills for doc %d (framework=%s)",
                        enriched_count, doc_id, framework)
        else:
            logger.info("Auto-enrich: no matching skills to enrich for doc %d", doc_id)

    except Exception as e:
        logger.error("Auto-enrich failed for doc %d: %s", doc_id, repr(e))
        db.rollback()
    finally:
        db.close()

# Valid values for ENUM columns
VALID_DELIVERABLE_TYPES = {'Document_Cadre', 'Charte_Contrat', 'Registre_Inventaire', 'Rapport_Audit', 'Configuration_Securite', 'Tache_Operationnelle'}
VALID_ACTORS = {'RSSI_Gouvernance', 'SecOps_CyberTech', 'Equipe_Infra_Ops', 'Directions_Metiers', 'RH_Juridique', 'Utilisateur_Final', 'DPO'}
VALID_GRC_CATEGORIES = {'Gouvernance', 'Technique', 'Physique', 'Resilience', 'Audit'}
VALID_FREQUENCIES = {'Ponctuel', 'Continu', 'Hebdomadaire', 'Mensuel', 'Trimestriel', 'Semestriel', 'Annuel', 'A chaque changement', 'Au_changement'}
VALID_CRITICALITIES = {'Mineure', 'Majeure', 'Critique', 'N/A'}
VALID_ENTRY_TYPES = {'requirement', 'information', 'definition'}

def _normalize_accents(s):
    """Normalize accented chars to match ENUM values (e.g. Résilience -> Resilience)."""
    if not s:
        return s
    import unicodedata
    return unicodedata.normalize('NFKD', s).encode('ASCII', 'ignore').decode('ASCII')


def _validate_enum(value, valid_set, default=None):
    """Return value if valid, else try accent-normalized, else default."""
    if value and value in valid_set:
        return value
    if value:
        normalized = _normalize_accents(value)
        if normalized in valid_set:
            return normalized
    return default


def _get_expected_column_count() -> int:
    """Read expected column count from ia_prompts.variables schema (reference_page_analysis).
    Falls back to 10 if schema is not available (new format with deliverable_id)."""
    try:
        from app.routers.ia_prompts import get_prompt_schema
        schema = get_prompt_schema("reference_page_analysis")
        if schema and isinstance(schema, dict) and "columns" in schema:
            cols = schema["columns"]
            if isinstance(cols, list) and len(cols) > 0:
                return len(cols)
    except Exception as e:
        logger.warning("Failed to read prompt schema, falling back to 10 columns: %s", repr(e))
    return 10


def _count_columns_in_result(result_text: str) -> int:
    """Count the number of columns in the first data row of a Markdown table result.
    Returns 0 if no data row is found."""
    if not result_text:
        return 0
    for line in result_text.split("\n"):
        line = line.strip()
        if not line.startswith("|"):
            continue
        if line.startswith("| ID / Reference") or line.startswith("| ID / Référence") or line.startswith("|---"):
            continue
        cols = [c.strip() for c in line.split("|")]
        cols = [c for c in cols if c != ""]
        return len(cols)
    return 0


def _post_process_requirements(doc_id: int):
    """Post-process requirements after parsing. Fixes misclassified entries."""
    from app.models import ReferenceRequirement, GovernanceDeliverable
    
    db = SessionLocal()
    try:
        reqs = db.query(ReferenceRequirement).filter(
            ReferenceRequirement.document_id == doc_id,
            ReferenceRequirement.deliverable_id == 0,
            ReferenceRequirement.entry_type == "requirement",
        ).all()
        
        if not reqs:
            return 0
        
        framework = db.query(ReferenceRequirement).filter(
            ReferenceRequirement.document_id == doc_id
        ).first()
        if not framework:
            return 0
        fw = framework.regulatory_framework
        
        deliverables = db.query(GovernanceDeliverable).filter(
            GovernanceDeliverable.regulatory_framework == fw,
            GovernanceDeliverable.is_active == True
        ).all()
        
        ACTION_VERBS = [
            "renouveler", "mettre a jour", "mettre à jour", "desactiver", "désactiver",
            "configurer", "verifier", "vérifier", "activer", "installer", "supprimer",
            "journaliser", "centraliser", "surveiller", "monitorer", "controler", "contrôler",
            "appliquer", "restaurer", "sauvegarder", "chiffrer", "durcir",
        ]
        
        INSTITUTIONAL_KEYWORDS = [
            "autorite de controle", "autorité de contrôle", "etats membres", "état membre",
            "etats membre", "commission europeenne", "commission européenne",
            "comite europeen", "comité européen", "enisa", "csirt", "eu-cyclone",
            "superviseur principal", "autorite competente", "autorité compétente",
            "organisme de certification", "groupe de cooperation", "amende administrative",
            "sanction", "astreinte", "commission soumet", "parlement europeen",
            "parlement européen", "conseil europeen", "conseil européen",
        ]
        
        fixed = 0
        for req in reqs:
            rule_lower = (req.rule or "").lower()
            
            is_institutional = any(kw in rule_lower for kw in INSTITUTIONAL_KEYWORDS)
            if is_institutional:
                req.compliance_status = "Non_applicable"
                fixed += 1
                continue
            
            if req.deliverable_type == "Document_Cadre":
                has_action_verb = any(verb in rule_lower for verb in ACTION_VERBS)
                if has_action_verb:
                    recurring_keywords = ["chaque annee", "chaque année", "chaque trimestre", "regulierement", "régulièrement",
                                          "quotidiennement", "hebdomadairement", "mensuellement", "continu", "en continu",
                                          "a jour", "à jour", "systematiquement", "systématiquement"]
                    if any(kw in rule_lower for kw in recurring_keywords):
                        req.deliverable_type = "Tache_Operationnelle"
                    else:
                        req.deliverable_type = "Configuration_Securite"
                    fixed += 1
                    continue
            
            if req.deliverable_type and req.deliverable_type != "Configuration_Securite":
                best_match = None
                best_score = 0
                for deliv in deliverables:
                    deliv_words = set((deliv.deliverable_name or "").lower().split())
                    rule_words = set(rule_lower.split())
                    common = deliv_words & rule_words
                    stop_words = {"de", "la", "le", "les", "des", "du", "un", "une", "et", "ou", "a", "à", "en", "au", "aux", "pour", "par", "sur", "dans", "est", "que", "qui", "ne", "pas", "ce", "se", "son", "sa", "ses"}
                    meaningful_common = common - stop_words
                    if len(meaningful_common) > best_score:
                        best_score = len(meaningful_common)
                        best_match = deliv
                
                if best_match and best_score >= 2:
                    req.deliverable_id = best_match.id
                    fixed += 1
        
        if fixed > 0:
            db.commit()
            logger.info("Post-process: fixed %d requirements for doc %d", fixed, doc_id)
        
        return fixed
    except Exception as e:
        logger.error("Post-process failed for doc %d: %s", doc_id, repr(e))
        db.rollback()
        return 0
    finally:
        db.close()


def _auto_parse_requirements(doc_id: int):
    """Auto-parse requirements after analysis completion. Called from _analyze_pages_background.
    Does NOT require auth — internal function. Idempotent: deletes existing requirements first.
    Pages with incorrect column count are marked as error in DB."""
    from app.models import ReferenceRequirement
    db = SessionLocal()
    try:
        # Récupère le regulatory_framework du document (via son organism)
        _framework = _get_doc_regulatory_framework(db, doc_id)
        done_pages = db.query(PolicyDocumentPage).filter(
            PolicyDocumentPage.document_id == doc_id,
            PolicyDocumentPage.status == "done"
        ).order_by(PolicyDocumentPage.page_number).all()

        # Delete existing requirements for this doc
        db.query(ReferenceRequirement).filter(ReferenceRequirement.document_id == doc_id).delete()

        expected_cols = _get_expected_column_count()
        parsed_count = 0
        error_pages = []

        for page in done_pages:
            if not page.result_text:
                continue
            # Check if page has the expected number of columns
            page_cols = _count_columns_in_result(page.result_text)
            if page_cols > 0 and page_cols < expected_cols:
                # Mark page as error — incorrect column count
                page.status = "error"
                page.error_message = f"Format incomplet: {page_cols} colonnes au lieu de {expected_cols}"
                error_pages.append(page.page_number)
                continue

            for line in page.result_text.split("\n"):
                line = line.strip()
                if not line.startswith("|"):
                    continue
                if line.startswith("| ID / Reference") or line.startswith("| ID / Référence") or line.startswith("|---") or line.startswith("| ref_id") or line.startswith("| ref_id |") or line.startswith("| entry_type"):
                    continue
                cols = [c.strip() for c in line.split("|")]
                cols = [c for c in cols if c != ""]
                if len(cols) < expected_cols:
                    # Skip individual malformed lines but don't mark whole page as error
                    continue
                # 10-column format: ref_id | entry_type | rule | target | grc_category | deliverable_id | deliverable_type | actor | freq | crit
                if len(cols) >= 10:
                    _entry_type = cols[1]
                    _rule = cols[2]
                    _target = cols[3]
                    _grc = cols[4]
                    _deliv_id_raw = cols[5]
                    _deliv_type_raw = cols[6]
                    _actor = cols[7]
                    _freq = cols[8]
                    _crit = cols[9]
                elif len(cols) >= 7:
                    # Fallback for shorter lines
                    _entry_type = cols[1] if len(cols) > 1 else "requirement"
                    _rule = cols[2] if len(cols) > 2 else ""
                    _target = cols[3] if len(cols) > 3 else None
                    _grc = cols[4] if len(cols) > 4 else None
                    _deliv_id_raw = cols[5] if len(cols) > 5 else None
                    _deliv_type_raw = cols[6] if len(cols) > 6 else None
                    _actor = cols[7] if len(cols) > 7 else None
                    _freq = cols[8] if len(cols) > 8 else None
                    _crit = cols[9] if len(cols) > 9 else None
                else:
                    continue

                # Parse deliverable_id as integer
                # 0 = technical requirement (no governance deliverable)
                # N/A or unparseable = institutional provision (authorities, not enterprise)
                _deliverable_id = 0  # default: technical/no deliverable
                if _deliv_id_raw and _deliv_id_raw not in ("N/A", "n/a", "NA"):
                    try:
                        _deliverable_id = int(_deliv_id_raw)
                    except (ValueError, TypeError):
                        _deliverable_id = 0  # fallback to 0 if not parseable

                # Parse deliverable_type
                _deliverable_type = _deliv_type_raw if _deliv_type_raw and _deliv_type_raw != "N/A" else None

                # Validate ENUM values
                _entry_type = _validate_enum(_entry_type, VALID_ENTRY_TYPES, "requirement")
                _grc = _validate_enum(_grc, VALID_GRC_CATEGORIES)
                _actor = _validate_enum(_actor, VALID_ACTORS)
                _freq = _validate_enum(_freq, VALID_FREQUENCIES)
                _crit = _validate_enum(_crit, VALID_CRITICALITIES)

                req = ReferenceRequirement(
                    document_id=doc_id,
                    page_number=page.page_number,
                    ref_id=cols[0] if len(cols) > 0 else None,
                    entry_type=_entry_type,
                    regulatory_framework=_framework,
                    rule=_rule,
                    target=_target,
                    control_type=None,
                    grc_category=_grc,
                    deliverable_type=_deliverable_type,
                    deliverable_id=_deliverable_id,
                    actor=_actor,
                    control_frequency=_freq,
                    criticality=_crit,
                    compliance_status="Non_traitee",
                )
                db.add(req)
                parsed_count += 1

        db.commit()
        logger.info("Auto-parsed %d requirements for doc %d, %d pages in error", parsed_count, doc_id, len(error_pages))
    except Exception as e:
        logger.error("Auto-parse failed for doc %d: %s", doc_id, repr(e))
        db.rollback()
    finally:
        db.close()


@router.post("/documents/{doc_id}/parse-requirements")
def parse_requirements(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Parse page-by-page AI results into reference_requirements table.
    Uses the column count from ia_prompts schema (dynamic).
    Pages with incorrect column count are marked as error in DB.
    Idempotent: deletes existing requirements for this doc before re-inserting."""
    from app.models import ReferenceRequirement

    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Récupère le regulatory_framework du document (priorité: doc.regulatory_framework > organism > ANSSI)
    _framework = _get_doc_regulatory_framework(db, doc_id) if hasattr(doc, 'regulatory_framework') and doc.regulatory_framework else _map_organism_to_framework(doc.organism) if doc.organism else "ANSSI"

    done_pages = db.query(PolicyDocumentPage).filter(
        PolicyDocumentPage.document_id == doc_id,
        PolicyDocumentPage.status == "done"
    ).order_by(PolicyDocumentPage.page_number).all()

    # Delete existing requirements for this doc
    db.query(ReferenceRequirement).filter(ReferenceRequirement.document_id == doc_id).delete()

    expected_cols = _get_expected_column_count()
    parsed_count = 0
    error_pages = []
    skipped_lines = 0

    for page in done_pages:
        if not page.result_text:
            continue

        # Check if page has the expected number of columns
        page_cols = _count_columns_in_result(page.result_text)
        if page_cols > 0 and page_cols < expected_cols:
            page.status = "error"
            page.error_message = f"Format incomplet: {page_cols} colonnes au lieu de {expected_cols}"
            error_pages.append({"page_number": page.page_number, "found": page_cols, "expected": expected_cols})
            continue

        for line in page.result_text.split("\n"):
            line = line.strip()
            if not line.startswith("|"):
                continue
            if line.startswith("| ID / Reference") or line.startswith("| ID / Référence") or line.startswith("|---") or line.startswith("| ref_id") or line.startswith("| ref_id |") or line.startswith("| entry_type"):
                continue

            cols = [c.strip() for c in line.split("|")]
            # Keep positions — do NOT remove empty strings (causes column shift)
            if cols and cols[0] == "":
                cols = cols[1:]
            if cols and cols[-1] == "":
                cols = cols[:-1]
            # Need at least 5 columns, skip if less
            if len(cols) < 5:
                continue

            # STRICT: require exactly expected_cols columns
            if len(cols) != expected_cols:
                logger.warning("Parser: doc %d page %d line has %d cols (expected %d), skipping: %s", doc_id, page.page_number, len(cols), expected_cols, line[:120])
                skipped_lines += 1
                continue
            # 10-column format: ref_id | entry_type | rule | target | grc_category | deliverable_id | deliverable_type | actor | freq | crit
            _entry_type = cols[1]
            _rule = cols[2]
            _target = cols[3]
            _grc = cols[4]
            _deliv_id_raw = cols[5]
            _actor = cols[6]
            _freq = cols[7]
            _crit = cols[8]

            # Parse deliverable_id as integer
            # 0 = technical/institutional (no governance deliverable)
            _deliverable_id = 0
            if _deliv_id_raw and _deliv_id_raw not in ("N/A", "n/a", "NA"):
                try:
                    _deliverable_id = int(_deliv_id_raw)
                except (ValueError, TypeError):
                    _deliverable_id = 0

            # Parse deliverable_type
            _deliverable_type = _deliv_type_raw if _deliv_type_raw and _deliv_type_raw != "N/A" else None

            # Validate ENUM values
            _entry_type = _validate_enum(_entry_type, VALID_ENTRY_TYPES, "requirement")
            _grc = _validate_enum(_grc, VALID_GRC_CATEGORIES)
            _actor = _validate_enum(_actor, VALID_ACTORS)
            _freq = _validate_enum(_freq, VALID_FREQUENCIES)
            _crit = _validate_enum(_crit, VALID_CRITICALITIES)

            req = ReferenceRequirement(
                document_id=doc_id,
                page_number=page.page_number,
                ref_id=cols[0],
                entry_type=_entry_type,
                regulatory_framework=_framework,
                rule=_rule,
                target=_target,
                control_type=None,
                grc_category=_grc,
                deliverable_type=_deliverable_type,
                deliverable_id=_deliverable_id,
                actor=_actor,
                control_frequency=_freq,
                criticality=_crit,
                compliance_status="Non_traitee",
            )
            db.add(req)
            parsed_count += 1

    db.commit()

    msg = f"{parsed_count} exigences integrees"
    if error_pages:
        msg += f", {len(error_pages)} pages en erreur (format incomplet)"

    return {
        "status": "ok",
        "parsed": parsed_count,
        "error_pages": error_pages,
        "expected_columns": expected_cols,
        "message": msg,
    }


@router.post("/documents/{doc_id}/compile-analysis")
def compile_analysis(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Compile page-by-page results into ai_analysis field."""
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    done_pages = db.query(PolicyDocumentPage).filter(
        PolicyDocumentPage.document_id == doc_id,
        PolicyDocumentPage.status == "done"
    ).order_by(PolicyDocumentPage.page_number).all()

    table_header = "| ID / Référence | Règle / Exigence | Cible | Catégorie GRC | Livrable ID | Acteur Destinataire | Fréquence | Criticité |\n|---|---|---|---|---|---|---|---|\n"
    table_rows = []
    for p in done_pages:
        if not p.result_text:
            continue
        for line in p.result_text.split("\n"):
            line = line.strip()
            if line.startswith("|") and not line.startswith("| ID / Reference") and not line.startswith("|---") and not line.startswith("| ID / Référence") and not line.startswith("| ref_id") and not line.startswith("| entry_type"):
                table_rows.append(line)

    if table_rows:
        doc.ai_analysis = table_header + "\n".join(table_rows)
        doc.ai_analysis += "\n\n---\n\n⚠️ Cette analyse a ete generee par une IA et ne se substitue pas a la lecture attentive du document original.\n"
    else:
        doc.ai_analysis = "Aucune exigence trouvee dans le document."
    doc.ai_analyzed_at = datetime.now(timezone.utc)
    doc.updated_at = datetime.now(timezone.utc)
    db.commit()

    return {"status": "ok", "rows": len(table_rows)}


@router.post("/documents/{doc_id}/analyze-pages")
async def analyze_pages(
    doc_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Start page-by-page analysis of a reference document in the background."""
    db = SessionLocal()
    try:
        # Test DB connection
        try:
            db.execute(__import__('sqlalchemy').text('SELECT 1'))
        except Exception:
            db.close()
            db = SessionLocal()

        doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
        if not doc.file_data:
            raise HTTPException(status_code=400, detail="Document has no file data")

        # Extract total pages
        fname = (doc.file_name or "").lower()
        if fname.endswith('.pdf') or doc.file_type == 'application/pdf':
            try:
                from PyPDF2 import PdfReader
                reader = PdfReader(io.BytesIO(doc.file_data))
                total_pages = len(reader.pages)
            except Exception as e:
                raise HTTPException(status_code=422, detail=f"Cannot read PDF: {e}")
        else:
            total_pages = 1

        # Capture data before closing
        _file_data = bytes(doc.file_data)
        _file_type = doc.file_type or ""
        _file_name = doc.file_name or ""

        # Delete existing page entries if any (re-analysis)
        db.query(PolicyDocumentPage).filter(PolicyDocumentPage.document_id == doc_id).delete()
        db.commit()

        # Create page entries
        for pn in range(1, total_pages + 1):
            page_row = PolicyDocumentPage(
                document_id=doc_id,
                page_number=pn,
                total_pages=total_pages,
                status="pending",
            )
            db.add(page_row)
        db.commit()

        # Capture file data for background task (detach from ORM)
        file_data = bytes(doc.file_data)
        file_type = doc.file_type or ""
        file_name = doc.file_name or ""

        # Close DB session before background task
        db.close()
    except HTTPException:
        db.close()
        raise
    except Exception:
        db.close()
        raise

    # Launch background task
    _enqueue_analysis(doc_id, total_pages, file_data, file_type, file_name)
    global _analysis_processor_task
    _analysis_processor_task = _asyncio_mod.ensure_future(_process_analysis_queue_safe())

    return {"status": "started", "total_pages": total_pages}


@router.post("/documents/{doc_id}/analyze-page/{page_num}")
async def analyze_single_page(
    doc_id: int,
    page_num: int,
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Analyze a single page of a document. Used to retry failed pages."""
    db = SessionLocal()
    try:
        doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
        if not doc.file_data:
            raise HTTPException(status_code=400, detail="Document has no file data")

        # Mark page as analyzing
        page_row = db.query(PolicyDocumentPage).filter(
            PolicyDocumentPage.document_id == doc_id,
            PolicyDocumentPage.page_number == page_num
        ).first()
        if not page_row:
            raise HTTPException(status_code=404, detail=f"Page {page_num} not found")
        page_row.status = "analyzing"
        page_row.error_message = None
        db.commit()

        _file_data = bytes(doc.file_data)
        _file_type = doc.file_type or ""
        _file_name = doc.file_name or ""
        _total = page_row.total_pages
    finally:
        db.close()

    # Launch single page analysis in background
    _asyncio_mod.ensure_future(_analyze_single_page(doc_id, page_num, _total, _file_data, _file_type, _file_name))

    return {"status": "started", "page": page_num}


@router.post("/documents/{doc_id}/analyze-error-pages")
async def analyze_error_pages(
    doc_id: int,
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Re-analyze all pages with status 'error' for a document."""
    db = SessionLocal()
    try:
        doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
        if not doc.file_data:
            raise HTTPException(status_code=400, detail="Document has no file data")

        error_pages = db.query(PolicyDocumentPage).filter(
            PolicyDocumentPage.document_id == doc_id,
            PolicyDocumentPage.status == "error"
        ).all()

        if not error_pages:
            return {"status": "ok", "message": "Aucune page en erreur", "pages": []}

        # Mark all error pages as analyzing
        page_nums = []
        for page_row in error_pages:
            page_row.status = "analyzing"
            page_row.error_message = None
            page_nums.append(page_row.page_number)

        db.commit()

        _file_data = bytes(doc.file_data)
        _file_type = doc.file_type or ""
        _file_name = doc.file_name or ""
        _total = error_pages[0].total_pages
    finally:
        db.close()

    # Launch each page analysis in background sequentially
    async def _analyze_all_errors():
        for pn in page_nums:
            await _analyze_single_page(doc_id, pn, _total, _file_data, _file_type, _file_name)

    _asyncio_mod.ensure_future(_analyze_all_errors())

    return {"status": "started", "pages": page_nums, "count": len(page_nums)}


async def _analyze_single_page(doc_id: int, page_num: int, total_pages: int, file_data: bytes, file_type: str, file_name: str):
    """Analyze a single page and update the result."""
    from app.routers.ia_prompts import get_prompt as _get_prompt
    import io as _io

    ollama_url = cfg_get("ollama.url", "http://127.0.0.1:11434")
    ollama_model = cfg_get("ollama.model", "qwen3:4b")
    ollama_timeout_raw = int(cfg_get("ollama.timeout", "30"))
    per_page_timeout = max(ollama_timeout_raw, 60) + 10

    prompt_template = _get_prompt("reference_page_analysis")

    # Extract the specific page text
    try:
        from PyPDF2 import PdfReader
        reader = PdfReader(_io.BytesIO(file_data))
        text = reader.pages[page_num - 1].extract_text() or ""
    except Exception as e:
        logger.error("Failed to extract page %d for doc %d: %s", page_num, doc_id, repr(e))
        db_err = SessionLocal()
        try:
            pr = db_err.query(PolicyDocumentPage).filter(
                PolicyDocumentPage.document_id == doc_id,
                PolicyDocumentPage.page_number == page_num
            ).first()
            if pr:
                pr.status = "error"
                pr.error_message = f"PDF extraction failed: {e}"
            db_err.commit()
        finally:
            db_err.close()
        return

    # Skip if text too short
    if not text or len(text.strip()) < 50:
        db_skip = SessionLocal()
        try:
            pr = db_skip.query(PolicyDocumentPage).filter(
                PolicyDocumentPage.document_id == doc_id,
                PolicyDocumentPage.page_number == page_num
            ).first()
            if pr:
                pr.status = "skipped"
                pr.result_text = "RIEN"
            db_skip.commit()
        finally:
            db_skip.close()
        return

    prompt = prompt_template.replace("{text}", text[:8000])
    payload = {
        "model": ollama_model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
            "think": _think_param(),
        "options": {"num_predict": 8192, "temperature": float(cfg_get("ollama.temperature", "0.1")), "num_ctx": int(cfg_get("ollama.context_length", "4096"))},
    }

    batch_timeout = max(float(per_page_timeout), 300.0)

    db_result = SessionLocal()
    try:
        try:
            async with httpx.AsyncClient(timeout=batch_timeout) as client:
                api_headers = {"Authorization": f"Bearer {cfg_get('ollama.api_key', '')}"} if cfg_get("ollama.api_key", "") else {}
                resp = await client.post(f"{ollama_url.rstrip('/')}/api/chat", json=payload, headers=api_headers)
                resp.raise_for_status()
                data = resp.json()
                result = (data.get("message", {}).get("content", "") or data.get("response", "") or "No response from AI").strip()

            if result.upper().strip() == "RIEN" or result.strip() == "":
                pr = db_result.query(PolicyDocumentPage).filter(
                    PolicyDocumentPage.document_id == doc_id,
                    PolicyDocumentPage.page_number == page_num
                ).first()
                if pr:
                    pr.status = "skipped"
                    pr.result_text = "RIEN"
                    pr.updated_at = datetime.now(timezone.utc)
            else:
                pr = db_result.query(PolicyDocumentPage).filter(
                    PolicyDocumentPage.document_id == doc_id,
                    PolicyDocumentPage.page_number == page_num
                ).first()
                if pr:
                    pr.status = "done"
                    pr.result_text = result
                    pr.updated_at = datetime.now(timezone.utc)
            db_result.commit()

        except Exception as e:
            logger.error("Error processing doc %d page %d: %s", doc_id, page_num, repr(e))
            pr = db_result.query(PolicyDocumentPage).filter(
                PolicyDocumentPage.document_id == doc_id,
                PolicyDocumentPage.page_number == page_num
            ).first()
            if pr:
                pr.status = "error"
                pr.error_message = str(e)[:500]
                pr.updated_at = datetime.now(timezone.utc)
            db_result.commit()
    finally:
        db_result.close()

    # Recompile ai_analysis after single page update
    try:
        db_compile = SessionLocal()
        doc = db_compile.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
        if doc:
            done_pages = db_compile.query(PolicyDocumentPage).filter(
                PolicyDocumentPage.document_id == doc_id,
                PolicyDocumentPage.status == "done"
            ).order_by(PolicyDocumentPage.page_number).all()

            table_header = "| ID / Référence | Règle / Exigence | Cible | Catégorie GRC | Livrable ID | Acteur Destinataire | Fréquence | Criticité |\n|---|---|---|---|---|---|---|---|\n"
            table_rows = []
            for p in done_pages:
                if not p.result_text:
                    continue
                for line in p.result_text.split("\n"):
                    line = line.strip()
                    if line.startswith("|") and not line.startswith("| ID / Reference") and not line.startswith("|---") and not line.startswith("| ID / Référence") and not line.startswith("| ref_id") and not line.startswith("| entry_type"):
                        table_rows.append(line)

            if table_rows:
                doc.ai_analysis = table_header + "\n".join(table_rows)
            else:
                doc.ai_analysis = "Aucune exigence trouvee dans le document."
            doc.ai_analyzed_at = datetime.now(timezone.utc)
            db_compile.commit()
    except Exception as e:
        logger.error("Failed to recompile after single page: %s", repr(e))
    finally:
        db_compile.close()

    # Re-parse requirements for this page if the doc was already integrated
    try:
        from app.models import ReferenceRequirement
        db_req = SessionLocal()
        existing = db_req.query(ReferenceRequirement).filter(
            ReferenceRequirement.document_id == doc_id
        ).count()
        if existing > 0:
            # Doc was already integrated — re-parse just this page
            # Récupère le regulatory_framework du document
            _framework_reparse = _get_doc_regulatory_framework(db_req, doc_id)
            db_req.query(ReferenceRequirement).filter(
                ReferenceRequirement.document_id == doc_id,
                ReferenceRequirement.page_number == page_num
            ).delete()

            page_row = db_req.query(PolicyDocumentPage).filter(
                PolicyDocumentPage.document_id == doc_id,
                PolicyDocumentPage.page_number == page_num,
                PolicyDocumentPage.status == "done"
            ).first()

            if page_row and page_row.result_text:
                expected_cols = _get_expected_column_count()
                # Check column count before parsing
                page_cols = _count_columns_in_result(page_row.result_text)
                if page_cols > 0 and page_cols < expected_cols:
                    page_row.status = "error"
                    page_row.error_message = f"Format incomplet: {page_cols} colonnes au lieu de {expected_cols}"
                    db_req.commit()
                    logger.warning("Page %d of doc %d has %d cols instead of %d — marked as error", page_num, doc_id, page_cols, expected_cols)
                else:
                    for line in page_row.result_text.split("\n"):
                        line = line.strip()
                        if not line.startswith("|"):
                            continue
                        if line.startswith("| ID / Reference") or line.startswith("| ID / Référence") or line.startswith("|---") or line.startswith("| ref_id") or line.startswith("| entry_type"):
                            continue
                        cols = [c.strip() for c in line.split("|")]
                        cols = [c for c in cols if c != ""]
                        if len(cols) < expected_cols:
                            continue
                        req = ReferenceRequirement(
                            document_id=doc_id,
                            page_number=page_num,
                            ref_id=cols[0] if len(cols) > 0 else None,
                            entry_type="requirement",
                            regulatory_framework=_framework_reparse,
                            rule=cols[1] if len(cols) > 1 else "",
                            target=cols[2] if len(cols) > 2 else None,
                            control_type=cols[3] if len(cols) > 3 else None,
                            grc_category=cols[4] if len(cols) > 4 else None,
                            deliverable_type=cols[5] if len(cols) > 5 else None,
                            actor=cols[6] if len(cols) > 6 else None,
                            control_frequency=cols[7] if len(cols) > 7 else None,
                            criticality=cols[8] if len(cols) > 8 else None,
                            compliance_status="Non_traitee",
                        )
                        db_req.add(req)
            db_req.commit()
            logger.warning("Re-parsed requirements for doc %d page %d", doc_id, page_num)
        db_req.close()
    except Exception as e:
        logger.error("Failed to re-parse requirements after single page: %s", repr(e))

    # Auto-enrich skills after single page re-parse (same as _analyze_pages_background)
    try:
        _auto_enrich_skills(doc_id)
    except Exception as e:
        logger.warning("Auto-enrich skills failed for doc %d after single page: %s", doc_id, repr(e))


@router.get("/documents/{doc_id}/analysis-progress")
def get_analysis_progress(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get progress of page-by-page analysis."""
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    pages = db.query(PolicyDocumentPage).filter(
        PolicyDocumentPage.document_id == doc_id
    ).order_by(PolicyDocumentPage.page_number).all()

    if not pages:
        return {
            "total_pages": 0,
            "analyzed_pages": 0,
            "pending_pages": 0,
            "skipped_pages": 0,
            "error_pages": 0,
            "status": "not_started",
            "current_page": 0,
            "pages": [],
        }

    total = len(pages)
    done = sum(1 for p in pages if p.status == "done")
    skipped = sum(1 for p in pages if p.status == "skipped")
    error = sum(1 for p in pages if p.status == "error")
    pending = sum(1 for p in pages if p.status == "pending")
    analyzing = sum(1 for p in pages if p.status == "analyzing")

    # Determine overall status
    # Check if this doc is in the queue
    in_queue = any(qid == doc_id for (qid, _, _, _, _) in _analysis_queue)

    if pending == total:
        overall = "pending" if in_queue else "not_started"
    elif analyzing > 0:
        overall = "analyzing"
    elif pending > 0 and (done + skipped + error) > 0:
        # Has some done pages + remaining pending = paused or queued
        overall = "pending" if in_queue else "paused"
    elif pending == 0 and analyzing == 0:
        if error > 0 and done > 0:
            overall = "partial"
        elif error > 0 and done == 0:
            overall = "error"
        else:
            overall = "done"
    else:
        overall = "analyzing"

    # Expected column count for needs_review comparison
    expected_cols = _get_expected_column_count()

    # Find current page (first analyzing or first pending after last done)
    current_page = 0
    for p in pages:
        if p.status == "analyzing":
            current_page = p.page_number
            break
    if current_page == 0:
        for p in pages:
            if p.status == "pending":
                current_page = p.page_number
                break
    if current_page == 0 and done > 0:
        current_page = total

    pages_list = []
    for p in pages:
        entry = {
            "page_number": p.page_number,
            "status": p.status,
        }
        if p.status == "done":
            preview = (p.result_text or "")[:100]
            entry["result_preview"] = preview
            # Dynamic needs_review: compare page columns with expected schema
            page_cols = _count_columns_in_result(p.result_text or "")
            entry["needs_review"] = page_cols > 0 and page_cols != expected_cols
            if entry["needs_review"]:
                entry["needs_review_reason"] = f"{page_cols} colonnes au lieu de {expected_cols}"
        elif p.status == "skipped":
            entry["result_preview"] = "RIEN"
            entry["needs_review"] = False
        elif p.status == "error":
            entry["result_preview"] = (p.error_message or "")[:100]
            entry["needs_review"] = False
        else:
            entry["needs_review"] = False
        pages_list.append(entry)

    return {
        "total_pages": total,
        "analyzed_pages": done,
        "pending_pages": pending,
        "skipped_pages": skipped,
        "error_pages": error,
        "status": overall,
        "current_page": current_page,
        "pages": pages_list,
    }


@router.get("/documents/{doc_id}/analysis-results")
def get_analysis_results(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get full analysis results for each page."""
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    pages = db.query(PolicyDocumentPage).filter(
        PolicyDocumentPage.document_id == doc_id
    ).order_by(PolicyDocumentPage.page_number).all()

    expected_cols = _get_expected_column_count()

    result = []
    for p in pages:
        entry = {
            "page_number": p.page_number,
            "status": p.status,
            "result_text": p.result_text,
            "error_message": p.error_message,
        }
        # Dynamic needs_review: compare page columns with current schema
        if p.status == "done" and p.result_text:
            page_cols = _count_columns_in_result(p.result_text)
            entry["needs_review"] = page_cols > 0 and page_cols != expected_cols
            if entry["needs_review"]:
                entry["needs_review_reason"] = f"{page_cols} colonnes au lieu de {expected_cols}"
            else:
                entry["needs_review_reason"] = None
        else:
            entry["needs_review"] = False
            entry["needs_review_reason"] = None
        result.append(entry)

    return result


@router.get("/documents/{doc_id}/analysis-download")
def download_analysis(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Download the full page-by-page analysis as a Markdown file."""
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    pages = db.query(PolicyDocumentPage).filter(
        PolicyDocumentPage.document_id == doc_id
    ).order_by(PolicyDocumentPage.page_number).all()

    if not pages:
        raise HTTPException(status_code=404, detail="No page analysis found for this document")

    lines = [
        f"# {doc.name}",
        "",
        f"**Date d'analyse :** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Document :** {doc.file_name}",
        f"**Pages totales :** {len(pages)}",
        "",
        "---",
        "",
    ]

    # Single table with all requirements
    table_header = "| ID / Référence | Règle / Exigence | Cible | Type de contrôle | Catégorie GRC | Type Livrable Cible | Acteur Destinataire | Fréquence | Criticité |\n|---|---|---|---|---|---|---|---|---|"
    table_rows = []
    for p in pages:
        if p.status == "done" and p.result_text and p.result_text.strip() != "RIEN":
            for line in p.result_text.split("\n"):
                line = line.strip()
                if line.startswith("|") and not line.startswith("| ID / Reference") and not line.startswith("| ID / Référence") and not line.startswith("|---") and not line.startswith("| ref_id") and not line.startswith("| entry_type"):
                    table_rows.append(line)

    if table_rows:
        lines.append("## Exigences extraites")
        lines.append("")
        lines.append(table_header)
        lines.extend(table_rows)
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("⚠️ Cette analyse a ete generee par une IA et ne se substitue pas a la lecture attentive du document original.")
    else:
        lines.append("Aucune exigence trouvee dans le document.")

    content = "\n".join(lines)
    safe_name = (doc.name or "analysis").replace(" ", "_").replace("/", "_")
    filename = f"{safe_name}_analysis.md"

    return Response(
        content=content.encode("utf-8"),
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


# ── Pre-analysis: determine regulatory_framework from document content ──

import re as _re_framework

# Quick detection by filename (no API call needed)
_FILENAME_FRAMEWORK_PATTERNS = [
    (r"(?i)nis\s*2|nis2|nis_2|nis_v\d|nis.v\d|recyf|32022l2555|celex.*l2555", "NIS2"),
    (r"(?i)rgpd|gdpr|cnil|protection.des.donn|32016r0679|celex.*0679", "RGPD"),
    (r"(?i)dora|digital.operational.resilience|32022r2554|celex.*r2554", "DORA"),
    (r"(?i)iso\s*27001|iso27001|iso_27001|27001", "ISO27001"),
    (r"(?i)pci.?dss|pci_dss", "PCI-DSS"),
    (r"(?i)bsi|bundesamt", "BSI"),
    (r"(?i)nist", "NIST"),
    (r"(?i)ebios", "ANSSI"),  # EBIOS is an ANSSI method
    (r"(?i)anssi|agence.nationale.s", "ANSSI"),
]


def _detect_framework_from_filename(filename: str) -> str | None:
    """Quick detection of regulatory framework from the document filename.
    Returns the framework code or None if no match."""
    if not filename:
        return None
    for pattern, framework in _FILENAME_FRAMEWORK_PATTERNS:
        if _re_framework.search(pattern, filename):
            return framework
    return None


def _store_pre_analysis(db, doc_id: int, framework: str, doc_type: str, summary: str, method: str, model: str, sample_pages: int, sample_chars: int):
    """Upsert pre-analysis result into document_pre_analysis table."""
    existing = db.query(DocumentPreAnalysis).filter(DocumentPreAnalysis.document_id == doc_id).first()
    if existing:
        existing.regulatory_framework = framework
        existing.document_type = doc_type
        existing.summary = summary
        existing.method = method
        existing.model_used = model
        existing.sample_pages = sample_pages
        existing.sample_chars = sample_chars
    else:
        pa = DocumentPreAnalysis(
            document_id=doc_id,
            regulatory_framework=framework,
            document_type=doc_type,
            summary=summary,
            method=method,
            model_used=model,
            sample_pages=sample_pages,
            sample_chars=sample_chars,
        )
        db.add(pa)
    db.commit()


def _pre_analyze_framework(db, doc_id: int) -> dict:
    """Pre-analyze a document to determine its regulatory_framework via IA.
    Extracts text from the PDF (file_data in DB) and asks the IA to identify the framework.
    Returns: {"regulatory_framework": "...", "summary": "...", "method": "ia"|"default"}
    """
    from app.models import PolicyDocument
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        _store_pre_analysis(db, doc_id, "ANSSI", "", "", "default", "", 0, 0)
        return {"regulatory_framework": "ANSSI", "document_type": "", "summary": "", "method": "default"}

    # Extract text from the PDF (file_data)
    sample_text = ""
    try:
        fname = doc.name or ""
        if fname.endswith('.pdf') or doc.file_type == 'application/pdf':
            import io as _io
            from PyPDF2 import PdfReader as _PdfReader
            reader = _PdfReader(_io.BytesIO(doc.file_data))
            total_pages = len(reader.pages)
            # Sample: first 3 + last 3 pages
            sample_indices = list(range(min(3, total_pages)))
            if total_pages > 6:
                sample_indices += list(range(total_pages - 3, total_pages))
            elif total_pages > 3:
                sample_indices += list(range(3, total_pages))
            for idx in sample_indices:
                page_text = reader.pages[idx].extract_text() or ""
                sample_text += page_text[:3000] + "\n\n"
            sample_text = sample_text[:16000]  # ~4000 tokens
            logger.info("Pre-analysis doc %d: extracted %d chars from %d sample pages (total %d pages)",
                        doc_id, len(sample_text), len(sample_indices), total_pages)
    except Exception as e:
        logger.warning("Pre-analysis doc %d: PDF text extraction failed: %s", doc_id, e)

    if not sample_text or len(sample_text.strip()) < 50:
        logger.info("Pre-analysis doc %d: no text available, defaulting to ANSSI", doc_id)
        _store_pre_analysis(db, doc_id, "ANSSI", "", "", "default", "", 0, 0)
        return {"regulatory_framework": "ANSSI", "document_type": "", "summary": "", "method": "default"}

    # Determine language from organization profile
    _org_lang = "fr"  # default
    try:
        from app.models import OrganizationProfile
        _profile = db.query(OrganizationProfile).filter(OrganizationProfile.status == "validated").first()
        if _profile and _profile.profile_data:
            import json as _json_lang
            _pd = _json_lang.loads(_profile.profile_data) if isinstance(_profile.profile_data, str) else _profile.profile_data
            _country = _pd.get("country", "") or _pd.get("pays", "")
            if _country and str(_country).upper() not in ("FR", "BE", "LU", "CH", "MC"):
                _org_lang = "en"
    except Exception:
        pass

    # Call IA with the extracted text
    if _org_lang == "fr":
        _lang_note = "Utilise les termes francophones pour les frameworks (ex: RGPD et non GDPR, NIS2, DORA, ISO27001)."
    else:
        _lang_note = "Use the standard international names for frameworks (ex: GDPR, NIS2, DORA, ISO27001)."

    prompt = (
        "Tu es un expert en conformite reglementaire europeenne et internationale. "
        "Voici un extrait d'un document. Identifie le cadre reglementaire principal ET le type de document. "
        f"{_lang_note}\n"
        "Reponds UNIQUEMENT en JSON: {\"regulatory_framework\": \"CADRE\", \"document_type\": \"TYPE\", \"summary\": \"resume en 2-3 phrases\"}\n"
        "Valeurs possibles pour regulatory_framework: ANSSI, RGPD, NIS2, DORA, ISO27001, BSI, NIST, PCI-DSS, etc. "
        "Si tu ne peux pas determiner le cadre, mets \"CUSTOM\".\n"
        "Valeurs possibles pour document_type: \n"
        "  - \"Reglement UE\" : reglement directement applicable (ex: DORA, RGPD). Reference typique: (UE) 2022/XXXX\n"
        "  - \"Directive UE\" : directive a transposer en droit national. Reference typique: (UE) 2022/XXEE\n"
        "  - \"Guide technique\" : guide methodologique, bonnes pratiques (ex: ANSSI, EBIOS RM)\n"
        "  - \"Loi nationale\" : loi ou decrets nationaux transposant une directive\n"
        "  - \"Norme internationale\" : norme ISO, IEC, NIST, etc.\n"
        "  - \"Autre\" : si aucun des types ci-dessus\n"
        "Le framework et le document_type doivent etre exactement comme indique ci-dessus.\n\n"
        f"Titre du document: {doc.name}\n\n"
        f"Extrait:\n{sample_text}"
    )

    try:
        ollama_url = cfg_get("ollama.url", "http://localhost:11434")
        ollama_model = cfg_get("ollama.model", "kimi-k2.6")
        ollama_api_key = cfg_get("ollama.api_key", "")
        ollama_timeout = max(int(cfg_get("ollama.timeout", "30")), 120)
        ollama_num_ctx = int(cfg_get("ollama.context_length", "4096"))

        import httpx
        headers = {"Authorization": f"Bearer {ollama_api_key}"} if ollama_api_key else {}
        with httpx.Client(timeout=float(ollama_timeout + 10)) as client:
            resp = client.post(
                f"{ollama_url.rstrip('/')}/api/chat",
                json={
                    "model": ollama_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
            "think": _think_param(),
                    "options": {
                        "num_predict": 2048,
                        "temperature": 0.3,
                        "num_ctx": ollama_num_ctx,
                    },
                },
                headers=headers,
            )
            resp.raise_for_status()
            result = resp.json()
            msg = result.get("message", {})
            text = msg.get("content", "") or result.get("response", "")

        # Parse JSON from response
        import json as _json_fw
        _json_match = _re_framework.search(r'\{[^}]+\}', text)
        if _json_match:
            parsed = _json_fw.loads(_json_match.group())
            fw = parsed.get("regulatory_framework", "ANSSI").upper().strip()
            doc_type = parsed.get("document_type", "").strip()
            summary = parsed.get("summary", "").strip()
            model_used = cfg_get("ollama.model", "unknown")
            logger.info("Pre-analysis doc %d: IA detected framework=%s, document_type=%s, summary=%s", doc_id, fw, doc_type, summary[:80])
            # Store in document_pre_analysis table (upsert)
            _store_pre_analysis(db, doc_id, fw, doc_type, summary, "ia", model_used, len(sample_indices), len(sample_text))
            return {"regulatory_framework": fw, "document_type": doc_type, "summary": summary, "method": "ia"}
    except Exception as e:
        logger.warning("Pre-analysis doc %d: IA call failed: %s, defaulting to ANSSI", doc_id, e)

    _store_pre_analysis(db, doc_id, "ANSSI", "", "", "default", "", 0, 0)
    return {"regulatory_framework": "ANSSI", "document_type": "", "summary": "", "method": "default"}


@router.post("/documents/{doc_id}/pre-analyze")
def pre_analyze_document(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "rssi", "dpo", "compliance_officer")),
):
    """Pre-analyze a document to determine its regulatory_framework.
    Uses filename detection first, then IA if needed.
    Updates the document.regulatory_framework in DB."""
    result = _pre_analyze_framework(db, doc_id)
    # Update document
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if doc:
        doc.regulatory_framework = result["regulatory_framework"]
        if result.get("document_type"):
            doc.document_type = result["document_type"]
        db.commit()
    return {"doc_id": doc_id, **result}


@router.put("/documents/{doc_id}/reclassify")
def reclassify_document(
    doc_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "rssi", "dpo")),
):
    """Manually reclassify a document's regulatory_framework.
    Cascades to all reference_requirements of this document."""
    from app.models import ReferenceRequirement as _RefReq
    new_fw = body.get("regulatory_framework", "").upper().strip()
    if not new_fw:
        raise HTTPException(status_code=400, detail="regulatory_framework is required")

    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    old_fw = doc.regulatory_framework
    doc.regulatory_framework = new_fw

    # Cascade: update all requirements that have the OLD framework (or ANSSI default) for this doc
    reqs = db.query(_RefReq).filter(
        _RefReq.document_id == doc_id
    ).all()
    updated = 0
    for req in reqs:
        if old_fw is None or req.regulatory_framework == old_fw or req.regulatory_framework == "ANSSI":
            req.regulatory_framework = new_fw
            updated += 1

    db.commit()
    logger.info("Reclassified doc %d: %s -> %s (%d requirements updated)", doc_id, old_fw, new_fw, updated)
    return {"doc_id": doc_id, "old_framework": old_fw, "new_framework": new_fw, "requirements_updated": updated}
# ═══════════════════════════════════════════════════════════
# OnlyOffice integration — view/edit documents from Bibliothèque
# ═══════════════════════════════════════════════════════════

import jwt as _jwt_mod
import os as _os_mod

_POLICY_ONLYOFFICE_SECRET = "HHdnWf2Ro+af5uPIQT1Nkf3uf/WlrTZhzqbfgYApGSaOadMG"
_POLICY_BACKEND_URL = "http://127.0.0.1:8000"


@router.get("/documents/{doc_id}/office-file")
def serve_office_file(doc_id: int, db: Session = Depends(get_db)):
    """Serve the document file for OnlyOffice (no auth — OnlyOffice needs direct access)."""
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return Response(
        content=doc.file_data,
        media_type=doc.file_type or "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={
            "Content-Disposition": f'inline; filename="{doc.file_name}"',
            "Content-Length": str(doc.file_size),
        },
    )


@router.get("/documents/{doc_id}/editor-config")
def get_office_editor_config(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Return OnlyOffice editor config with JWT. Mode view/edit based on user role."""
    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Determine edit permission
    user_role = current_user.role if hasattr(current_user, 'role') else 'viewer'
    can_edit = user_role in ("admin", "superadmin", "rssi", "dpo")
    mode = "edit" if can_edit else "view"

    doc_key = f"pol_{doc_id}_{doc.revision or 1}"
    doc_url = f"{_POLICY_BACKEND_URL}/api/v1/policies/documents/{doc_id}/office-file"
    callback_url = f"{_POLICY_BACKEND_URL}/api/v1/policies/documents/{doc_id}/office-callback"

    config = {
        "document": {
            "fileType": "docx",
            "key": doc_key,
            "title": doc.name,
            "url": doc_url,
            "permissions": {
                "edit": can_edit,
                "download": True,
                "review": can_edit,
                "comment": can_edit,
                "print": True,
                "fillForms": False,
                "modifyFilter": can_edit,
                "modifyContentControl": can_edit,
            },
        },
        "editorConfig": {
            "mode": mode,
            "lang": "fr",
            "callbackUrl": callback_url if can_edit else "",
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

    token = _jwt_mod.encode(config, _POLICY_ONLYOFFICE_SECRET, algorithm="HS256")
    config["token"] = token

    return config


@router.post("/documents/{doc_id}/office-callback")
async def office_callback(doc_id: int, request: Request, db: Session = Depends(get_db)):
    """Handle OnlyOffice save callback for Bibliothèque documents."""
    body = await request.body()
    try:
        data = json.loads(body)
    except Exception:
        data = json.loads(body.decode("utf-8"))

    status = data.get("status")
    logger.info("OnlyOffice callback for policy doc %d: status=%s", doc_id, status)

    doc = db.query(PolicyDocument).filter(PolicyDocument.id == doc_id).first()
    if not doc:
        return {"error": 1}

    if status in (2, 6):
        url = data.get("url")
        if url:
            try:
                with httpx.Client(timeout=60) as client:
                    resp = client.get(url)
                    resp.raise_for_status()
                    doc.file_data = resp.content
                    doc.file_size = len(resp.content)
                    doc.revision = (doc.revision or 1) + 1
                    doc.updated_at = datetime.now(timezone.utc)
                    db.commit()
                    logger.info("Policy doc %d saved via OnlyOffice", doc_id)
            except Exception as e:
                logger.error("Error saving policy doc %d: %s", doc_id, e)
                return {"error": 1}

    return {"error": 0}



def _link_requirements_to_assets(doc_id: int):
    """Event-driven: create asset_requirement_links for each requirement whose
    target is mapped in target_asset_mappings. Source de verite: la table de
    mapping (editable via /admin/target-mappings). Idempotent.
    v2.1 (10/09): resolve_asset_id n'existe plus depuis la reecriture v2 du
    resolver (multi-assets) — l'ancien import echouait silencieusement."""
    db = SessionLocal()
    try:
        from app.target_mapping import resolve_assets_for_target
        from app.models import AssetRequirementLink
        reqs = db.query(ReferenceRequirement).filter(
            ReferenceRequirement.document_id == doc_id,
            ReferenceRequirement.entry_type == "requirement",
        ).all()
        created = 0
        for r in reqs:
            if not r.target:
                continue
            asset_ids = resolve_assets_for_target(r.target, db)
            if not asset_ids:
                continue
            for asset_id in asset_ids:
                exists = db.query(AssetRequirementLink).filter(
                    AssetRequirementLink.requirement_id == r.id,
                    AssetRequirementLink.asset_id == asset_id,
                ).first()
                if exists:
                    continue
                db.add(AssetRequirementLink(
                    requirement_id=r.id,
                    asset_id=asset_id,
                    link_type="direct",
                ))
                created += 1
        db.commit()
        if created:
            logger.info("Target mapping: %d asset links created for doc %d", created, doc_id)
    except Exception as e:
        logger.warning("Target-mapping links failed for doc %d: %s", doc_id, repr(e))
    finally:
        db.close()


def _ai_relink_requirements(doc_id: int):
    """Use IA to link requirements that remained at deliverable_id=0 (excluding Configuration_Securite).
    Sends batches of requirements to the IA with the list of deliverables for the framework.
    The IA returns the best matching deliverable_id for each requirement.
    """
    import httpx
    from app.config_loader import get as cfg_get, _think_param
    from app.models import ReferenceRequirement, GovernanceDeliverable
    import json
    import re

    logger = logging.getLogger("logsoc.ai_relink")

    db = SessionLocal()
    try:
        # Get entries that need relinking — CONDITION POSITIVE sur destination:
        # seules les entrées explicitement à rattacher passent (requirements,
        # informations et définitions). Les techniques (destination='technique')
        # et institutionnelles ('institutionnel') ne sont JAMAIS soumises.
        reqs = db.query(ReferenceRequirement).filter(
            ReferenceRequirement.document_id == doc_id,
            ReferenceRequirement.deliverable_id == 0,
            (ReferenceRequirement.destination == "a_rattacher")
            | ((ReferenceRequirement.destination.is_(None)) &
               (ReferenceRequirement.entry_type == "requirement") &
               (ReferenceRequirement.compliance_status == "Non_traitee") &
               (ReferenceRequirement.deliverable_type != "Configuration_Securite")),
        ).all()

        if not reqs:
            return 0

        # Get framework
        framework = reqs[0].regulatory_framework if reqs else None
        if not framework:
            return 0

        # Get deliverables for this framework
        deliverables = db.query(GovernanceDeliverable).filter(
            GovernanceDeliverable.regulatory_framework == framework,
            GovernanceDeliverable.is_active == True
        ).all()

        if not deliverables:
            return 0

        # Build deliverables list for prompt
        deliv_list = "\n".join(f"   {d.id} = {d.deliverable_name}" for d in deliverables)

        # Process in batches of 10
        batch_size = 10
        total_linked = 0

        ollama_url = cfg_get("ollama.url", "http://localhost:11434")
        ollama_model = cfg_get("ollama.model", "glm-5.2")
        api_key = cfg_get("ollama.api_key", "")

        system_prompt = """Tu es un expert en gouvernance SI. Ton role est de rattacher des entrees (exigences, informations, definitions) a des livrables de gouvernance.

Les INFORMATIONS et DEFINITIONS sont des appuis de redaction: rattache l entree au livrable dont elle est la matiere premiere (le document ou ce contenu trouvera sa place). Si le contenu est du contexte general ou s adresse aux autorites, mets 0.

REGLES DE SECURITE:
- Tu ne reponds qu'aux questions relatives au rattachement.
- Tu refuses toute question hors sujet.

FORMAT DE REPONSE: JSON strict. Pour chaque entree, retourne un objet avec "id" (l ID de l entree) et "deliverable_id" (l ID du livrable correspondant, ou 0 si aucun ne correspond).

Exemple:
{"results": [{"id": 123, "deliverable_id": 45}, {"id": 124, "deliverable_id": 0}]}

IMPORTANT: Choisis le livrable le plus pertinent par correspondance SEMANTIQUE (pas juste par mots-cles). Si aucune correspondance, mets 0."""

        for i in range(0, len(reqs), batch_size):
            batch = reqs[i:i + batch_size]

            # Build requirements list for prompt
            reqs_text = "\n".join(
                f"   ID {r.id}: [{r.entry_type}/{r.deliverable_type}] {r.rule[:200]}"
                for r in batch
            )

            user_prompt = f"""Voici {len(batch)} exigences du framework {framework}:

{reqs_text}

Voici les livrables disponibles:
{deliv_list}

Pour chaque exigence, trouve le livrable le plus pertinent. Reponds en JSON strict avec le format: {{"results": [{{"id": <requirement_id>, "deliverable_id": <livrable_id_or_0>}}]}}"""

            payload = {
                "model": ollama_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
            "think": _think_param(),
                "format": "json",
                "options": {
                    "num_predict": 2048,
                    "temperature": 0.2,
                    "num_ctx": 16384,
                },
            }
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

            try:
                with httpx.Client(timeout=60) as client:
                    resp = client.post(
                        f"{ollama_url.rstrip('/')}/api/chat",
                        json=payload,
                        headers=headers,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    content = data.get("message", {}).get("content", "")

                result = json.loads(content)
                for item in result.get("results", []):
                    req_id = item.get("id")
                    deliv_id = item.get("deliverable_id", 0)
                    if req_id and deliv_id and deliv_id > 0:
                        # Verify the deliverable exists
                        if any(d.id == deliv_id for d in deliverables):
                            req = db.query(ReferenceRequirement).filter(ReferenceRequirement.id == req_id).first()
                            if req and req.deliverable_id == 0:
                                req.deliverable_id = deliv_id
                                req.destination = "livrable"
                                total_linked += 1

                db.commit()
                logger.info("AI relink batch %d: linked %d requirements", i // batch_size, total_linked)

            except Exception as e:
                logger.warning("AI relink batch %d failed: %s", i // batch_size, repr(e))
                continue

        if total_linked > 0:
            logger.info("AI relink: linked %d requirements for doc %d", total_linked, doc_id)

        return total_linked
    except Exception as e:
        logger.error("AI relink failed for doc %d: %s", doc_id, repr(e))
        db.rollback()
        return 0
    finally:
        db.close()
