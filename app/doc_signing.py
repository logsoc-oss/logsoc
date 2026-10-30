"""Signature électronique des documents de gouvernance (LogSOC).

Circuit: editing -> to_validate -> pdf_ready -> signed -> published
- Conversion .docx -> PDF via OnlyOffice ConvertService (DocumentServer local)
- Signature PDF PKCS#7 avec cachet visible (pyHanko + certificat autosigné)
- 2 catégories: signatory (métier, rôle requis par le livrable) + direction
- published exige les 2 signatures
- Hash SHA256 stocké, vérifiable
"""
import hashlib
import logging
import os
from datetime import datetime, timezone

import httpx
from sqlalchemy.orm import Session

from app.config_loader import get as cfg_get
from app.models import GovernanceDocument, GovernanceDeliverable, DocumentSignature, User
from app.roles import match_any, first_match

logger = logging.getLogger("logsoc.docsign")

CERT_PATH = "/opt/logsoc-web/certs/logsoc-doc-signing.p12"
CERT_PASS = "logsoc"
DOCS_DIR = "/opt/logsoc-web/documents"

# Rôles métier autorisés à contre-signer pour la direction
DIRECTION_ROLES = ("gerant", "president", "dg", "direction")


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


async def convert_docx_to_pdf(doc: GovernanceDocument) -> str:
    """Convertit le .docx du document en PDF via OnlyOffice ConvertService.
    Retourne le chemin du PDF généré."""
    onlyoffice_url = cfg_get("onlyoffice.url", "https://onlyoffice.example.com")
    src_path = doc.file_path
    if not os.path.exists(src_path):
        raise FileNotFoundError(f"Fichier source introuvable: {src_path}")

    # L'URL publique que le DocumentServer doit pouvoir récupérer
    public_base = cfg_get("onlyoffice.public_url", "https://logsoc.example.com/api/v1/governance-docs/file")
    file_url = f"{public_base}/{doc.id}"
    ext = os.path.splitext(doc.file_name)[1] or ".docx"

    payload = {
        "async": False,
        "filetype": ext.lstrip("."),
        "key": f"conv-{doc.id}-{int(datetime.now(timezone.utc).timestamp())}",
        "outputtype": "pdf",
        "title": os.path.splitext(doc.file_name)[0] + ".pdf",
        "url": file_url,
    }
    headers = {}
    token = cfg_get("onlyoffice.jwt_secret", "")
    if token:
        try:
            import jwt as pyjwt
            tok = pyjwt.encode({"payload": payload}, token, algorithm="HS256")
            headers["Authorization"] = f"Bearer {tok}"
        except Exception:
            pass

    async with httpx.AsyncClient(timeout=120.0, verify=False) as client:
        r = await client.post(
            f"{onlyoffice_url}/conversion-service", json=payload, headers=headers
        )
        r.raise_for_status()
        data = r.json()

    if data.get("error"):
        raise RuntimeError(f"OnlyOffice conversion error: {data.get('error')}")
    if not data.get("endConvert"):
        raise RuntimeError("OnlyOffice conversion timeout (endConvert=false)")

    pdf_url = data.get("fileUrl")
    if not pdf_url:
        raise RuntimeError("OnlyOffice conversion: pas de fileUrl")

    # Télécharger le PDF converti
    pdf_name = os.path.splitext(doc.file_name)[0] + ".pdf"
    pdf_path = os.path.join(DOCS_DIR, f"doc-{doc.id}-v{doc.version}.pdf")
    async with httpx.AsyncClient(timeout=120.0, verify=False) as client:
        r = await client.get(pdf_url)
        r.raise_for_status()
        with open(pdf_path, "wb") as f:
            f.write(r.content)

    return pdf_path


def _required_business_role(deliverable: GovernanceDeliverable) -> list:
    """Les rôles métier autorisés à signer le livrable (verification_role).
    Supporte les formats multi-rôles: 'DSI / Juriste / DPO' -> ['dsi','juriste','dpo']
    (n'importe lequel suffit)."""
    raw = (getattr(deliverable, "verification_role", None) or "").strip().lower()
    mapping = {
        "rssi": "rssi", "dpo": "dpo", "dsi": "dsi", "dg": "gerant",
        "president": "president", "gerant": "gerant", "compliance": "compliance",
        "juriste": "juriste", "cost strat": "gerant", "costrat": "gerant",
    }
    parts = [p.strip() for p in raw.split("/") if p.strip()]
    roles = []
    for p in parts:
        roles.append(mapping.get(p, p))
    return roles


def sign_pdf(pdf_path: str, out_path: str, signer_name: str, signer_role: str,
             category: str, doc_label: str) -> str:
    """Signe le PDF: (1) cachet texte visible en derniere page, (2) signature
    PKCS#7 cryptographique. Retourne le hash SHA256 du PDF signe."""
    from pyhanko.sign import signers
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.stamp import TextStampStyle, TextStamp

    signer = signers.SimpleSigner.load_pkcs12(
        CERT_PATH, passphrase=CERT_PASS.encode()
    )

    with open(pdf_path, "rb") as f:
        r = PdfFileReader(f)
        n_pages = len(r.root["/Pages"]["/Kids"])

    now = datetime.now(timezone.utc)
    stamp_text = (
        f"Signature: {category_label(category)}\n"
        f"Signataire: {signer_name}\n"
        f"Fonction: {signer_role or 'signataire'}\n"
        f"Date: {now.strftime('%d/%m/%Y %H:%M UTC')}"
    )

    style = TextStampStyle(stamp_text=stamp_text, border_width=0.8)

    field_name = f"Sig_{category}_{int(now.timestamp())}"

    with open(pdf_path, "rb") as fin:
        w = IncrementalPdfFileWriter(fin)

        # (1) Cachet visible en derniere page — 2e signature decalee
        x = 320 if category == "direction" else 60
        stamp = TextStamp(w, style)
        stamp.apply(n_pages - 1, x, 90)

        # (2) Signature PKCS#7 (champ invisible, valeur cryptographique)
        meta = signers.PdfSignatureMetadata(
            field_name=field_name,
            reason="Validation du document de gouvernance",
            name=signer_name,
        )
        with open(out_path, "wb") as fout:
            signers.sign_pdf(
                w, meta, signer=signer, output=fout,
            )

    return _sha256(out_path)


def category_label(cat: str) -> str:
    return {
        "signatory": "Signataire métier",
        "direction": "Validation direction",
        "rssi": "Signature RSSI — Rapport d'audit",
    }.get(cat, cat)


def check_sign_permission(user: User, doc: GovernanceDocument, db: Session, category: str) -> tuple:
    """Vérifie si l'utilisateur peut signer cette catégorie. Retourne (ok, erreur)."""
    if not getattr(user, "is_signatory", False):
        return False, "Vous n'êtes pas déclaré signataire"

    if category == "direction":
        if not match_any(user, DIRECTION_ROLES):
            br = (getattr(user, "business_role", None) or "").lower()
            return False, f"La contre-signature direction requiert le rôle Gérant/DG (rôle actuel: {br or 'non défini'})"
        return True, None

    if category == "signatory":
        deliverable = db.query(GovernanceDeliverable).filter(
            GovernanceDeliverable.id == doc.deliverable_id
        ).first()
        if not deliverable:
            return False, "Livrable introuvable"
        required = _required_business_role(deliverable)
        if required and not match_any(user, required):
            br = (getattr(user, "business_role", None) or "").lower()
            return False, f"Ce livrable requiert le rôle {' ou '.join(required)} (rôle actuel: {br or 'non défini'})"
        return True, None

    return False, "Catégorie inconnue"


def signatures_complete(doc: GovernanceDocument, db: Session) -> bool:
    """Un document est publié quand les 2 catégories sont signées."""
    cats = {
        s.category for s in db.query(DocumentSignature).filter(
            DocumentSignature.document_id == doc.id
        ).all()
    }
    return "signatory" in cats and "direction" in cats


def verify_document(doc: GovernanceDocument, db: Session) -> dict:
    """Vérifie l'intégrité: hash du PDF actuel vs hash signé."""
    sigs = db.query(DocumentSignature).filter(
        DocumentSignature.document_id == doc.id
    ).order_by(DocumentSignature.signed_at).all()
    result = {"signatures": [], "complete": signatures_complete(doc, db)}
    # Progression du cycle de validation direction (unanimité)
    try:
        from app.doc_validation import cycle_progress, validators_for_doc
        result["validation_cycle"] = cycle_progress(doc, db)
        result["validators"] = validators_for_doc(doc, db)
    except Exception:
        pass
    for s in sigs:
        entry = {
            "category": s.category, "signer": s.signer_display_name,
            "role": s.signer_business_role,
            "signed_at": s.signed_at.isoformat() if s.signed_at else None,
            "hash": s.signature_hash[:16] + "…",
            "pdf_integrity": None,
        }
        if s.pdf_path and os.path.exists(s.pdf_path):
            current = _sha256(s.pdf_path)
            entry["pdf_integrity"] = "OK" if current == s.signature_hash else "ALTERÉ"
        result["signatures"].append(entry)
    return result