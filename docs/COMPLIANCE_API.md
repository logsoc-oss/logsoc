# LOGSOC-WEB — Compliance API Documentation

Backend compliance modules reference for the LOGSOC-WEB platform.

---

## Table of Contents

1. [General Notes](#1-general-notes)
2. [Compliance (Generic)](#2-compliance-generic)
3. [NIS2](#3-nis2)
4. [DORA](#4-dora)
5. [RGPD Extended](#5-rgpd-extended)
6. [ISO 27001](#6-iso-27001)
7. [AI Act](#7-ai-act)
8. [Regulatory Notifications](#8-regulatory-notifications)
9. [NIS2 Multi-Country](#9-nis2-multi-country)
10. [Cross-Mapping](#10-cross-mapping)
11. [Reporting](#11-reporting)
12. [SOAR](#12-soar)

---

## 1. General Notes

### Authentication
- All endpoints require a valid **JWT** token in the `Authorization` header:
  ```
  Authorization: Bearer <jwt_token>
  ```
- Unless explicitly documented, no endpoint is public.

### Request / Response Format
- Format: **JSON**
- Request bodies must include the header:
  ```
  Content-Type: application/json
  ```
- Error responses follow this shape:
  ```json
  {
    "detail": "human-readable error message"
  }
  ```
  Common HTTP codes: `400`, `401`, `403`, `404`, `422`.

### Pagination
List endpoints support:
- `limit` — default `100`, maximum `500`
- `offset` — default `0`

Example:
```
GET /api/v1/dora/incidents?limit=50&offset=100
```

### Filtering
Filters are passed as **query parameters**. Supported filters are documented per endpoint.

### Storage
- **ClickHouse** is used for events and high-volume telemetry.
- **MariaDB** is used for compliance metadata and relational entities.

---

## 2. Compliance (Generic)

**Prefix:** `/api/v1/compliance`

Generic compliance overview endpoints covering the main frameworks: RGPD, NIS2, DORA, ISO 27001.

### Endpoints

#### `GET /api/v1/compliance/controls`
List all controls across frameworks.

- **Auth:** JWT
- **Query filters:** `framework`, `status`, `search`, `limit`, `offset`
- **Response:**
  ```json
  {
    "items": [
      {
        "id": 1,
        "framework": "NIS2",
        "code": "NIS2-ART21-A",
        "title": "Politique de sécurité du réseau et de l'information",
        "status": "implemented",
        "evidence": "https://docs.example.com/nis2/policy.pdf",
        "updated_at": "2026-06-19T12:00:00Z"
      }
    ],
    "total": 128,
    "limit": 100,
    "offset": 0
  }
  ```

#### `GET /api/v1/compliance/scores`
Return compliance score percentages per framework.

- **Auth:** JWT
- **Response:**
  ```json
  {
    "RGPD": 87.5,
    "NIS2": 72.0,
    "DORA": 65.0,
    "ISO27001": 91.0
  }
  ```

#### `GET /api/v1/compliance/controls/{control_id}`
Get a single control by ID.

- **Auth:** JWT
- **Response:** control object (see list example).

#### `PUT /api/v1/compliance/controls/{control_id}`
Update control status and evidence.

- **Auth:** JWT
- **Body:**
  ```json
  {
    "status": "partially_implemented",
    "evidence": "https://docs.example.com/evidence/2026-06.pdf",
    "notes": "En attente de validation RSSI"
  }
  ```
- **Response:** updated control object.

### Notes & Pitfalls
- `status` values are normalized across frameworks (e.g., `not_started`, `partially_implemented`, `implemented`, `not_applicable`).
- Updating a generic control may also update the corresponding module-specific record depending on backend mapping.

---

## 3. NIS2

**Prefix:** `/api/v1/nis2`

Implements Directive (EU) 2022/2555 — NIS2.

### Database Tables
- `nis2_classification`
- `nis2_measures`
- `nis2_assessment`
- `nis2_governance`

### Endpoints

#### `GET /api/v1/nis2/classification`
Get current entity classification (Essential Entity / Important Entity).

- **Auth:** JWT
- **Response:**
  ```json
  {
    "id": 1,
    "entity_type": "EE",
    "sector": "energy",
    "employees": 250,
    "revenue": 50000000,
    "is_critical": true,
    "identified_risks": ["supply_chain", "cyber_attack"],
    "updated_at": "2026-06-19T12:00:00Z"
  }
  ```

#### `PUT /api/v1/nis2/classification`
Update entity classification.

- **Auth:** JWT
- **Body:** `ClassificationUpdate`
  ```json
  {
    "entity_type": "EE",
    "sector": "energy",
    "employees": 300,
    "revenue": 75000000,
    "is_critical": true,
    "identified_risks": ["ransomware", "third_party_failure"]
  }
  ```
- **Response:** updated classification object.

#### `GET /api/v1/nis2/measures`
List the 10 NIS2 Article 21 §2 measures (a-j).

- **Auth:** JWT
- **Response:** array of measures.

#### `GET /api/v1/nis2/measures/{measure_code}`
Get one measure with its current assessment.

- **Auth:** JWT
- **Response:**
  ```json
  {
    "code": "NIS2-ART21-A",
    "title": "Politique de sécurité du réseau et de l'information",
    "description": "...",
    "assessment": {
      "status": "implemented",
      "maturity": 4,
      "evidence": "...",
      "gaps": [],
      "remediation_plan": null,
      "due_date": null
    }
  }
  ```

#### `PUT /api/v1/nis2/measures/{measure_id}/assessment`
Update assessment for a measure.

- **Auth:** JWT
- **Body:** `AssessmentUpdate`
  ```json
  {
    "status": "partially_implemented",
    "maturity": 3,
    "evidence": "https://docs.example.com/nis2/art21a.pdf",
    "gaps": ["manque de revue trimestrielle"],
    "remediation_plan": "Planifier revue trimestrielle dès Q3",
    "due_date": "2026-09-30"
  }
  ```
- **Response:** updated assessment object.

#### `GET /api/v1/nis2/governance`
List governance records (Article 20).

- **Auth:** JWT
- **Query filters:** `date_from`, `date_to`, `limit`, `offset`
- **Response:** array of governance records.

#### `POST /api/v1/nis2/governance`
Create a governance record.

- **Auth:** JWT
- **Body:** `GovernanceCreate`
  ```json
  {
    "action": "Rapportage mensuel au comité de direction",
    "description": "Présentation des indicateurs de sécurité du mois de mai",
    "date": "2026-06-15",
    "participants": ["RSSI", "DPO", "DSI"]
  }
  ```
- **Response:** created record with `id`.

#### `GET /api/v1/nis2/summary`
Return NIS2 summary.

- **Auth:** JWT
- **Response:**
  ```json
  {
    "compliance_score": 72.0,
    "average_maturity": 3.2,
    "status_distribution": {
      "implemented": 4,
      "partially_implemented": 4,
      "not_started": 2,
      "not_applicable": 0
    }
  }
  ```

### Notes & Pitfalls
- `measure_code` uses the canonical format `NIS2-ART21-A` to `NIS2-ART21-J`.
- `maturity` is an integer from `1` (initial) to `5` (optimizing).
- Classification changes may trigger a recalculation of applicable obligations.

---

## 4. DORA

**Prefix:** `/api/v1/dora`

Implements Regulation (EU) 2022/2554 — Digital Operational Resilience Act.

### Database Tables
- `dora_incidents`
- `dora_third_parties`
- `dora_resilience_tests`
- `dora_governance`

### Endpoints

#### `GET /api/v1/dora/pillars`
List the 5 DORA pillars.

- **Auth:** JWT
- **Response:** array of pillars.

#### `PUT /api/v1/dora/pillars/{pillar}`
Update a DORA pillar.

- **Auth:** JWT
- **Body:** `DoraGovernanceUpdate`
  ```json
  {
    "status": "in_progress",
    "owner": "rssi@example.com",
    "notes": "Cartographie ICT en cours de validation"
  }
  ```
- **Response:** updated pillar object.

#### `POST /api/v1/dora/incidents`
Classify and create an ICT incident.

- **Auth:** JWT
- **Body:** `DoraIncidentClassify`
  ```json
  {
    "title": "Panne majeure du core banking",
    "description": "Indisponibilité du système de paiement pendant 45 minutes",
    "severity": "major",
    "detection_time": "2026-06-19T10:30:00Z",
    "systems_affected": ["core-banking", "payment-gateway"],
    "impact": "Interruption partielle des opérations de paiement",
    "category": "availability"
  }
  ```
- **Response:** created incident with `id`.

#### `GET /api/v1/dora/incidents`
List incidents.

- **Auth:** JWT
- **Query filters:** `status`, `severity`, `limit`, `offset`
- **Response:** paginated list of incidents.

#### `GET /api/v1/dora/incidents/{incident_id}`
Get one incident.

- **Auth:** JWT
- **Response:** incident object.

#### `GET /api/v1/dora/third-parties`
List TIC third parties.

- **Auth:** JWT
- **Query filters:** `criticality`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/dora/third-parties`
Create a TIC third-party record.

- **Auth:** JWT
- **Body:** `DoraThirdPartyCreate`
  ```json
  {
    "name": "CloudSec Provider",
    "type": "cloud_provider",
    "criticality": "high",
    "contract_ref": "CTR-2026-0042",
    "dpa_signed": true,
    "exit_strategy": "Migration vers fournisseur B sous 90 jours",
    "concentration_risk": "medium"
  }
  ```
- **Response:** created third party with `id`.

#### `PUT /api/v1/dora/third-parties/{tp_id}`
Update a third party.

- **Auth:** JWT
- **Body:** `DoraThirdPartyUpdate` (same fields as create, optional)
- **Response:** updated third party object.

#### `DELETE /api/v1/dora/third-parties/{tp_id}`
Delete a third party.

- **Auth:** JWT
- **Response:** `204 No Content` on success.

#### `GET /api/v1/dora/resilience-tests`
List resilience tests.

- **Auth:** JWT
- **Query filters:** `type`, `status`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/dora/resilience-tests`
Create a resilience test.

- **Auth:** JWT
- **Body:** `DoraResilienceTestCreate`
  ```json
  {
    "type": "penetration_test",
    "scope": "Applications critiques de paiement",
    "planned_date": "2026-07-15",
    "status": "planned",
    "results": null,
    "remediation": null
  }
  ```
- **Response:** created test with `id`.

#### `PUT /api/v1/dora/resilience-tests/{test_id}`
Update a resilience test.

- **Auth:** JWT
- **Body:** `DoraResilienceTestUpdate`
- **Response:** updated test object.

#### `GET /api/v1/dora/summary`
Return DORA summary.

- **Auth:** JWT
- **Response:** summary object.

### Notes & Pitfalls
- `severity` values: `minor`, `major`, `critical`.
- Third-party `criticality` impacts reporting obligations and concentration-risk thresholds.
- Deleting a third party does **not** cascade to linked incidents or tests.

---

## 5. RGPD Extended

**Prefix:** `/api/v1/gdpr-ext`

Implements Regulation (EU) 2016/679 — GDPR.

### Database Tables
- `gdpr_treatments`
- `gdpr_dpia`
- `gdpr_data_requests`
- `gdpr_subprocessors`
- `gdpr_transfers`
- `gdpr_breaches`

### Endpoints

#### `GET /api/v1/gdpr-ext/treatments`
List Article 30 treatment records.

- **Auth:** JWT
- **Query filters:** `legal_basis`, `dpia_required`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/gdpr-ext/treatments`
Create a treatment record.

- **Auth:** JWT
- **Body:** `TreatmentCreate`
  ```json
  {
    "name": "Gestion des candidatures",
    "purpose": "Recrutement",
    "legal_basis": "consent",
    "data_categories": ["identity", "contact", "professional"],
    "recipients": ["rh", "hiring_manager"],
    "retention_period": "2 ans après le dernier contact",
    "third_country_transfer": false,
    "dpia_required": false
  }
  ```
- **Response:** created treatment with `id`.

#### `GET /api/v1/gdpr-ext/treatments/{treatment_id}`
Get one treatment.

- **Auth:** JWT
- **Response:** treatment object.

#### `DELETE /api/v1/gdpr-ext/treatments/{treatment_id}`
Delete a treatment.

- **Auth:** JWT
- **Response:** `204 No Content` on success.

#### `GET /api/v1/gdpr-ext/dpia`
List DPIAs (Article 35).

- **Auth:** JWT
- **Query filters:** `status`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/gdpr-ext/dpia`
Create a DPIA.

- **Auth:** JWT
- **Body:** `DpiaCreate`
  ```json
  {
    "treatment_id": 12,
    "description": "Traitement de biométrie pour contrôle d'accès",
    "necessity_proportionality": "Nécessaire et proportionné au objectifs de sécurité",
    "risk_assessment": "Risque élevé sur données biométriques",
    "measures": ["chiffrement", "pseudonymisation", "audit"],
    "residual_risk": "modéré"
  }
  ```
- **Response:** created DPIA with `id`.

#### `PUT /api/v1/gdpr-ext/dpia/{dpia_id}/approve`
Approve a DPIA.

- **Auth:** JWT
- **Response:** updated DPIA object with `approved_at` and `approved_by`.

#### `GET /api/v1/gdpr-ext/requests`
List data subject requests (Articles 12-22).

- **Auth:** JWT
- **Query filters:** `status`, `type`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/gdpr-ext/requests`
Create a data subject request.

- **Auth:** JWT
- **Body:** `DataRequestCreate`
  ```json
  {
    "type": "access",
    "data_subject_name": "Marie Dupont",
    "data_subject_email": "marie.dupont@example.com",
    "description": "Demande d'accès aux données personnelles",
    "deadline": "2026-07-19"
  }
  ```
- **Response:** created request with `id`.

#### `PUT /api/v1/gdpr-ext/requests/{request_id}`
Update a data subject request.

- **Auth:** JWT
- **Body:** `DataRequestUpdate`
  ```json
  {
    "status": "closed",
    "response": "Données fournies sous format CSV",
    "closed_at": "2026-06-19T15:00:00Z"
  }
  ```
- **Response:** updated request object.

#### `GET /api/v1/gdpr-ext/subprocessors`
List subprocessors (Article 28).

- **Auth:** JWT
- **Query filters:** `status`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/gdpr-ext/subprocessors`
Create a subprocessor record.

- **Auth:** JWT
- **Body:** `SubprocessorCreate`
  ```json
  {
    "name": "SendGrid",
    "type": "email_service",
    "dpa_signed": true,
    "dpa_date": "2026-01-15",
    "certifications": ["ISO 27001", "SOC 2 Type II"],
    "location": "USA",
    "safeguards": "SCC 2021/914"
  }
  ```
- **Response:** created subprocessor with `id`.

#### `DELETE /api/v1/gdpr-ext/subprocessors/{sub_id}`
Delete a subprocessor.

- **Auth:** JWT
- **Response:** `204 No Content` on success.

#### `GET /api/v1/gdpr-ext/transfers`
List transfers outside the EU (Articles 44-49).

- **Auth:** JWT
- **Query filters:** `country`, `mechanism`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/gdpr-ext/transfers`
Create a transfer record.

- **Auth:** JWT
- **Body:** `TransferCreate`
  ```json
  {
    "treatment_id": 12,
    "destination_country": "US",
    "mechanism": "SCC",
    "safeguards": "SCC 2021/914 + TIA",
    "tia_required": true,
    "tia_result": "acceptable_with_supplementary_measures"
  }
  ```
- **Response:** created transfer with `id`.

#### `GET /api/v1/gdpr-ext/breaches`
List personal data breaches (Articles 33-34).

- **Auth:** JWT
- **Query filters:** `status`, `severity`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/gdpr-ext/breaches`
Create a breach record.

- **Auth:** JWT
- **Body:** `BreachCreate`
  ```json
  {
    "title": "Exfiltration de données clients",
    "description": "Accès non autorisé à une base de données clients",
    "detection_time": "2026-06-18T08:00:00Z",
    "affected_data": ["email", "phone"],
    "affected_persons": 1250,
    "severity": "high",
    "cnil_notified": false,
    "notification_deadline": "2026-06-20T08:00:00Z"
  }
  ```
- **Response:** created breach with `id`.

#### `PUT /api/v1/gdpr-ext/breaches/{breach_id}`
Update a breach.

- **Auth:** JWT
- **Body:** `BreachUpdate`
  ```json
  {
    "status": "notified",
    "cnil_notified": true,
    "notification_date": "2026-06-19T10:00:00Z",
    "persons_notified": true,
    "remediation": "Réinitialisation des accès et audit complet"
  }
  ```
- **Response:** updated breach object.

#### `GET /api/v1/gdpr-ext/summary`
Return GDPR summary, including overdue requests.

- **Auth:** JWT
- **Response:** summary object.

### Notes & Pitfalls
- `type` for data subject requests: `access`, `rectification`, `erasure`, `portability`, `objection`, `restriction`.
- Breach notification deadline is **72 hours** from detection; the summary endpoint highlights late items.
- Deleting a treatment does **not** automatically delete linked DPIAs or transfers.

---

## 6. ISO 27001

**Prefix:** `/api/v1/iso27001`

Implements ISO/IEC 27001:2022 management system.

### Database Tables
- `iso27001_soa`
- `iso27001_audits`
- `iso27001_nonconformities`
- `iso27001_management_reviews`
- `iso27001_certifications`

### Endpoints

#### `GET /api/v1/iso27001/soa`
List the 93 Annex A controls.

- **Auth:** JWT
- **Query filters:** `family`, `status`, `limit`, `offset`
- **Response:** paginated list.

#### `GET /api/v1/iso27001/soa/{control_id}`
Get one Annex A control.

- **Auth:** JWT
- **Response:** control object.

#### `PUT /api/v1/iso27001/soa/{control_id}`
Update a Statement of Applicability entry.

- **Auth:** JWT
- **Body:** `SoaUpdate`
  ```json
  {
    "applicable": true,
    "justification": "Contrôle applicable à tous les systèmes d'information",
    "implementation_status": "implemented",
    "evidence": "https://docs.example.com/iso/a5.1.pdf",
    "owner": "rssi@example.com",
    "cross_mapping": ["NIS2-ART21-A", "DORA-ICT-RM"]
  }
  ```
- **Response:** updated control object.

#### `GET /api/v1/iso27001/audits`
List audits.

- **Auth:** JWT
- **Query filters:** `type`, `status`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/iso27001/audits`
Create an audit.

- **Auth:** JWT
- **Body:** `AuditCreate`
  ```json
  {
    "type": "internal",
    "scope": "Annex A 2022 — familles A.5 à A.8",
    "planned_date": "2026-08-10",
    "auditor": "Auditeur interne",
    "status": "planned"
  }
  ```
- **Response:** created audit with `id`.

#### `PUT /api/v1/iso27001/audits/{audit_id}`
Update an audit.

- **Auth:** JWT
- **Body:** `AuditUpdate`
  ```json
  {
    "status": "completed",
    "findings": ["NC mineure sur A.5.7"],
    "report_url": "https://docs.example.com/audits/2026-08.pdf",
    "closed_at": "2026-08-20T12:00:00Z"
  }
  ```
- **Response:** updated audit object.

#### `GET /api/v1/iso27001/nonconformities`
List nonconformities.

- **Auth:** JWT
- **Query filters:** `severity`, `status`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/iso27001/nonconformities`
Create a nonconformity.

- **Auth:** JWT
- **Body:** `NonconformityCreate`
  ```json
  {
    "audit_id": 5,
    "control_id": "A.5.7",
    "description": "Politique de classification non appliquée aux nouveaux projets",
    "severity": "minor",
    "root_cause": "Manque de sensibilisation",
    "corrective_action": "Formation + checklist projet",
    "due_date": "2026-09-30"
  }
  ```
- **Response:** created NC with `id`.

#### `PUT /api/v1/iso27001/nonconformities/{nc_id}`
Update a nonconformity.

- **Auth:** JWT
- **Body:** `NonconformityUpdate`
  ```json
  {
    "status": "closed",
    "effectiveness_check": "Contrôle projet validé sur 3 nouveaux projets",
    "closed_at": "2026-09-15T10:00:00Z"
  }
  ```
- **Response:** updated NC object.

#### `GET /api/v1/iso27001/management-reviews`
List management reviews (Article 9.3).

- **Auth:** JWT
- **Query filters:** `status`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/iso27001/management-reviews`
Create a management review.

- **Auth:** JWT
- **Body:** `ManagementReviewCreate`
  ```json
  {
    "date": "2026-06-30",
    "inputs": ["résultats audits", "NC", "indicateurs SOC"],
    "outputs": ["plan d'amélioration Q3"],
    "decisions": ["Validation du budget sécurité"],
    "status": "planned"
  }
  ```
- **Response:** created review with `id`.

#### `GET /api/v1/iso27001/certification`
List certifications.

- **Auth:** JWT
- **Response:** array of certifications.

#### `POST /api/v1/iso27001/certification`
Create a certification record.

- **Auth:** JWT
- **Body:** `CertificationCreate`
  ```json
  {
    "body": "Bureau Veritas",
    "scope": "SI de la société ABC — sites de Paris et Lyon",
    "issue_date": "2025-03-15",
    "surveillance_date": "2026-03-15",
    "recertification_date": "2028-03-15",
    "status": "active"
  }
  ```
- **Response:** created certification with `id`.

#### `GET /api/v1/iso27001/summary`
Return ISO 27001 summary.

- **Auth:** JWT
- **Response:**
  ```json
  {
    "implementation_rate": 91.0,
    "open_nonconformities": 2,
    "theme_distribution": {
      "A.5": 12,
      "A.6": 8,
      "A.7": 15,
      "A.8": 58
    }
  }
  ```

### Notes & Pitfalls
- `control_id` follows ISO/IEC 27001:2022 Annex A notation (e.g., `A.5.1`, `A.8.1`).
- `implementation_status` values: `not_started`, `in_progress`, `implemented`, `not_applicable`.
- Surveillance and recertification dates drive dashboard alerts.

---

## 7. AI Act

**Prefix:** `/api/v1/aiact`

Implements Regulation (EU) 2024/1689 — AI Act.

### Database Tables
- `aiact_systems`
- `aiact_classifications`
- `aiact_obligations`
- `aiact_incidents`
- `aiact_transparency`

### Endpoints

#### `GET /api/v1/aiact/systems`
List AI systems.

- **Auth:** JWT
- **Query filters:** `risk_level`, `provider`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/aiact/systems`
Create an AI system record.

- **Auth:** JWT
- **Body:** `AiSystemCreate`
  ```json
  {
    "name": "Système de scoring crédit",
    "provider": "Internal",
    "version": "2.1.0",
    "purpose": "Évaluation automatique des demandes de crédit",
    "data_used": ["données financières", "données comportementales"],
    "deployment_context": "secteur financier"
  }
  ```
- **Response:** created system with `id`.

#### `GET /api/v1/aiact/systems/{system_id}`
Get one AI system.

- **Auth:** JWT
- **Response:** system object.

#### `DELETE /api/v1/aiact/systems/{system_id}`
Delete an AI system.

- **Auth:** JWT
- **Response:** `204 No Content` on success.

#### `POST /api/v1/aiact/classify`
Classify risk level of an AI system.

- **Auth:** JWT
- **Body:** `AiClassificationCreate`
  ```json
  {
    "system_id": 7,
    "answers": {
      "prohibited_practices": [false, false, false, false, false, false, false, false, false],
      "annex_iii_categories": [false, false, true, false, false, false, false, false],
      "safety_component": false
    }
  }
  ```
- **Response:** classification result with `risk_level`.

#### `GET /api/v1/aiact/systems/{system_id}/obligations`
Get deployer obligations (Article 26).

- **Auth:** JWT
- **Response:** list of obligations.

#### `PUT /api/v1/aiact/systems/{system_id}/obligations`
Update deployer obligations.

- **Auth:** JWT
- **Response:** updated obligations object.

#### `GET /api/v1/aiact/incidents`
List serious incidents (Article 26 §5bis).

- **Auth:** JWT
- **Query filters:** `status`, `severity`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/aiact/incidents`
Create an AI incident.

- **Auth:** JWT
- **Body:** `AiIncidentCreate`
  ```json
  {
    "system_id": 7,
    "description": "Biais de genre détecté dans les recommandations de recrutement",
    "severity": "high",
    "detection_time": "2026-06-18T09:00:00Z",
    "provider_notified": false,
    "authority_notified": false
  }
  ```
- **Response:** created incident with `id`.

#### `PUT /api/v1/aiact/incidents/{incident_id}`
Update an AI incident.

- **Auth:** JWT
- **Body:** `AiIncidentUpdate`
  ```json
  {
    "status": "notified",
    "provider_notified": true,
    "authority_notified": true,
    "notification_date": "2026-06-19T10:00:00Z",
    "remediation": "Réentraînement du modèle avec dataset équilibré"
  }
  ```
- **Response:** updated incident object.

#### `GET /api/v1/aiact/transparency`
List transparency obligations (Article 50).

- **Auth:** JWT
- **Response:** paginated list.

#### `PUT /api/v1/aiact/transparency/{trans_id}`
Update a transparency obligation.

- **Auth:** JWT
- **Body:** `AiTransparencyUpdate`
  ```json
  {
    "status": "implemented",
    "disclosure_text": "Cette interaction est gérée par une IA générative.",
    "content_marked": true,
    "emotion_recognition_disclosed": true
  }
  ```
- **Response:** updated transparency object.

#### `GET /api/v1/aiact/summary`
Return AI Act summary.

- **Auth:** JWT
- **Response:** summary object with risk-level distribution.

### Notes & Pitfalls
- `risk_level` values: `prohibited`, `high`, `limited`, `minimal`.
- Classification answers must cover the 9 prohibited practices of Article 5, the 8 Annex III categories, and the safety-component flag.
- High-risk systems trigger the most obligations; prohibited systems must be disabled.

---

## 8. Regulatory Notifications

**Prefix:** `/api/v1/notifications`

Manages regulatory notification workflows and timers.

### Database Tables
- `regulatory_notifications`
- `regulatory_notification_timers`
- `regulatory_templates`

### Endpoints

#### `POST /api/v1/notifications/trigger`
Trigger a regulatory notification.

- **Auth:** JWT
- **Body:** `NotificationTrigger`
  ```json
  {
    "regulation": "GDPR",
    "event_type": "data_breach",
    "entity_id": 42,
    "description": "Violation de données personnelles détectée",
    "deadline_hours": 72
  }
  ```
- **Response:** created notification with `id` and timer.

#### `GET /api/v1/notifications/`
List notifications.

- **Auth:** JWT
- **Query filters:** `regulation`, `status`, `limit`, `offset`
- **Response:** paginated list.

#### `GET /api/v1/notifications/{notif_id}`
Get notification detail.

- **Auth:** JWT
- **Response:** notification object.

#### `PUT /api/v1/notifications/{notif_id}`
Update a notification.

- **Auth:** JWT
- **Body:** `NotificationUpdate`
  ```json
  {
    "status": "sent",
    "content": "Notification CNIL envoyée le 19/06/2026",
    "sent_at": "2026-06-19T10:00:00Z",
    "acknowledged_at": "2026-06-19T11:00:00Z"
  }
  ```
- **Response:** updated notification object.

#### `GET /api/v1/notifications/templates/{regulation}`
List templates for a regulation.

- **Auth:** JWT
- **Regulations:** `nis2`, `dora`, `gdpr`, `aiact`
- **Response:** array of templates.

#### `POST /api/v1/notifications/{notif_id}/render`
Render a notification from its template.

- **Auth:** JWT
- **Response:** rendered content.

#### `GET /api/v1/notifications/timers/pending`
List pending notification timers with countdown.

- **Auth:** JWT
- **Response:** array of timers.

#### `POST /api/v1/notifications/timers/{timer_id}/ack`
Acknowledge a timer.

- **Auth:** JWT
- **Response:** updated timer object.

#### `GET /api/v1/notifications/summary`
Return notifications summary.

- **Auth:** JWT
- **Response:** summary object.

### Notes & Pitfalls
- `deadline_hours` drives the countdown timer; missing it may result in late regulatory notifications.
- Rendering from template does **not** send the notification automatically.

---

## 9. NIS2 Multi-Country

**Prefix:** `/api/v1/nis2-countries`

Tracks NIS2 transposition status across the 27 EU member states.

### Database Tables
- `nis2_countries`
- `nis2_authorities`
- `nis2_country_requirements`

### Endpoints

#### `GET /api/v1/nis2-countries/countries`
List the 27 EU member states.

- **Auth:** JWT
- **Query filters:** `transposition_status`, `limit`, `offset`
- **Response:** paginated list.

#### `GET /api/v1/nis2-countries/countries/{country_code}`
Get country detail.

- **Auth:** JWT
- **Response:**
  ```json
  {
    "country_code": "FR",
    "name": "France",
    "transposition_status": "adopted",
    "national_framework": "ANSSI / Loi n°2024-XX",
    "sanctions": "Jusqu'à 2% du CA mondial annuel"
  }
  ```

#### `GET /api/v1/nis2-countries/countries/{country_code}/authority`
Get the competent national authority.

- **Auth:** JWT
- **Response:** authority object (e.g., ANSSI, BSI, ACN, CCB).

#### `GET /api/v1/nis2-countries/summary`
Return transposition summary.

- **Auth:** JWT
- **Response:** summary object.

### Notes & Pitfalls
- `country_code` is the ISO 3166-1 alpha-2 code (e.g., `FR`, `DE`, `NL`).
- Transposition statuses may be `not_started`, `in_progress`, `adopted`, `in_force`.

---

## 10. Cross-Mapping

**Prefix:** `/api/v1/mapping`

Cross-mapping between 11 compliance frameworks.

### Database Tables
- `mapping_frameworks`
- `mapping_controls`
- `mapping_cross`

### Frameworks
1. NIS2
2. DORA
3. RGPD
4. AI Act
5. ISO 27001
6. NIST CSF 2.0
7. CIS v8
8. ANSSI 42
9. PCI-DSS v4
10. SOC 2
11. EBIOS RM

### Endpoints

#### `GET /api/v1/mapping/frameworks`
List the 11 frameworks.

- **Auth:** JWT
- **Response:** array of frameworks.

#### `GET /api/v1/mapping/controls`
List the 60 controls.

- **Auth:** JWT
- **Query filters:** `framework`, `limit`, `offset`
- **Response:** paginated list.

#### `GET /api/v1/mapping/cross`
List the 64 cross-mappings.

- **Auth:** JWT
- **Query filters:** `framework`, `match_type`, `limit`, `offset`
- **Response:** paginated list.

#### `GET /api/v1/mapping/{fw1}/{fw2}`
Get mapping between two specific frameworks.

- **Auth:** JWT
- **Example:** `GET /api/v1/mapping/NIS2/ISO27001`
- **Response:** mapping object.

#### `GET /api/v1/mapping/unified-dashboard`
Get unified multi-framework dashboard.

- **Auth:** JWT
- **Response:** aggregated dashboard data.

#### `GET /api/v1/mapping/summary`
Return mapping summary.

- **Auth:** JWT
- **Response:** summary object.

### Notes & Pitfalls
- `match_type` values: `exact`, `partial`, `related`.
- Framework identifiers in URLs are case-sensitive and use the canonical short names listed above.

---

## 11. Reporting

**Prefix:** `/api/v1/reports`

Reporting dashboards, templates, schedules, and history.

### Database Tables
- `report_dashboards`
- `report_templates`
- `report_schedules`
- `report_history`

### Dashboards (8)
1. Direction
2. RSSI/DPO
3. Analyste SOC
4. Audit
5. Conformité
6. Risques
7. TI
8. SOAR

### Templates (6)
1. NIS2
2. DORA
3. RGPD
4. ISO 27001
5. Incidents mensuel
6. Risques trimestriel

### Endpoints

#### `GET /api/v1/reports/dashboards`
List the 8 dashboards.

- **Auth:** JWT
- **Response:** array of dashboards.

#### `GET /api/v1/reports/dashboards/{dashboard_type}`
Get dashboard configuration.

- **Auth:** JWT
- **Response:** dashboard config object.

#### `GET /api/v1/reports/dashboards/{dashboard_type}/data`
Get aggregated dashboard data.

- **Auth:** JWT
- **Response:** dashboard data object.

#### `GET /api/v1/reports/templates`
List the 6 report templates.

- **Auth:** JWT
- **Query filters:** `framework`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/reports/generate`
Generate a report.

- **Auth:** JWT
- **Body:** `GenerateRequest`
  ```json
  {
    "template_id": 3,
    "format": "pdf",
    "date_from": "2026-05-01",
    "date_to": "2026-05-31",
    "filters": {
      "framework": "NIS2"
    }
  }
  ```
- **Response:** report history entry with `id` and `download_url`.

#### `GET /api/v1/reports/schedules`
List scheduled reports.

- **Auth:** JWT
- **Query filters:** `is_active`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/reports/schedules`
Create a scheduled report.

- **Auth:** JWT
- **Body:** `ScheduleCreate`
  ```json
  {
    "template_id": 5,
    "cron": "0 9 1 * *",
    "format": "pdf",
    "recipients": ["rssi@example.com", "direction@example.com"]
  }
  ```
- **Response:** created schedule with `id`.

#### `DELETE /api/v1/reports/schedules/{schedule_id}`
Delete a schedule.

- **Auth:** JWT
- **Response:** `204 No Content` on success.

#### `GET /api/v1/reports/history`
List report generation history.

- **Auth:** JWT
- **Query filters:** `template`, `status`, `limit`, `offset`
- **Response:** paginated list.

#### `GET /api/v1/reports/summary`
Return reporting summary.

- **Auth:** JWT
- **Response:** summary object.

### Notes & Pitfalls
- `format` values: `pdf`, `xlsx`, `csv`, `html`.
- `cron` expressions use standard 5-field format.
- Generated reports are asynchronous; poll `/history` for `status`.

---

## 12. SOAR

**Prefix:** `/api/v1/soar`

Security Orchestration, Automation and Response.

### Database Tables
- `soar_playbooks`
- `soar_executions`
- `soar_approvals`
- `soar_integrations`

### Triggers (5)
1. `alert_created`
2. `incident_created`
3. `ioc_detected`
4. `vuln_critical`
5. `manual`
6. `scheduled`

### Seed Playbooks (5)
1. Phishing
2. Malware
3. Vuln critique
4. NIS2 auto-trigger
5. RGPD breach auto-trigger

### Endpoints

#### `GET /api/v1/soar/playbooks`
List playbooks.

- **Auth:** JWT
- **Query filters:** `trigger`, `is_active`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/soar/playbooks`
Create a playbook.

- **Auth:** JWT
- **Body:** `PlaybookCreate`
  ```json
  {
    "name": "Isolation post-détection IOC",
    "trigger": "ioc_detected",
    "steps": [
      {"action": "enrich_ioc", "params": {}},
      {"action": "block_ip", "params": {"duration": 86400}}
    ],
    "description": "Bloque automatiquement les IOCs de criticité élevée",
    "is_active": true
  }
  ```
- **Response:** created playbook with `id`.

#### `GET /api/v1/soar/playbooks/{playbook_id}`
Get one playbook.

- **Auth:** JWT
- **Response:** playbook object.

#### `PUT /api/v1/soar/playbooks/{playbook_id}`
Update a playbook.

- **Auth:** JWT
- **Body:** `PlaybookUpdate`
  ```json
  {
    "name": "Isolation post-détection IOC v2",
    "steps": [
      {"action": "enrich_ioc", "params": {}},
      {"action": "block_ip", "params": {"duration": 172800}},
      {"action": "notify_soc", "params": {}}
    ],
    "is_active": true,
    "trigger": "ioc_detected"
  }
  ```
- **Response:** updated playbook object.

#### `DELETE /api/v1/soar/playbooks/{playbook_id}`
Delete a playbook.

- **Auth:** JWT
- **Response:** `204 No Content` on success.

#### `POST /api/v1/soar/execute`
Execute a playbook.

- **Auth:** JWT
- **Body:** `ExecuteRequest`
  ```json
  {
    "playbook_id": 4,
    "context": {"alert_id": 1234, "severity": "high"},
    "trigger_data": {"ioc": "192.0.2.100", "type": "ip"}
  }
  ```
- **Response:** execution object with `execution_id` and `status`.

#### `GET /api/v1/soar/executions`
List playbook executions.

- **Auth:** JWT
- **Query filters:** `playbook`, `status`, `limit`, `offset`
- **Response:** paginated list.

#### `GET /api/v1/soar/executions/{exec_id}`
Get execution detail.

- **Auth:** JWT
- **Response:** execution object with step logs.

#### `GET /api/v1/soar/approvals/pending`
List pending human approvals.

- **Auth:** JWT
- **Response:** array of approvals.

#### `POST /api/v1/soar/approvals/{approval_id}`
Decide on a pending approval.

- **Auth:** JWT
- **Body:** `ApprovalDecision`
  ```json
  {
    "decision": "approve",
    "comment": "Action validée après vérification de l'IOC"
  }
  ```
- **Response:** updated approval object.

#### `GET /api/v1/soar/integrations`
List integrations.

- **Auth:** JWT
- **Query filters:** `is_active`, `limit`, `offset`
- **Response:** paginated list.

#### `POST /api/v1/soar/integrations`
Create an integration.

- **Auth:** JWT
- **Body:** `IntegrationCreate`
  ```json
  {
    "name": "TheHive",
    "type": "case_management",
    "config": {"url": "https://thehive.example.com", "api_key": "***"},
    "is_active": true
  }
  ```
- **Response:** created integration with `id`.

#### `PUT /api/v1/soar/integrations/{integ_id}/test`
Test an integration.

- **Auth:** JWT
- **Response:** test result object.

#### `GET /api/v1/soar/summary`
Return SOAR summary.

- **Auth:** JWT
- **Response:** summary object with success rate.

### Notes & Pitfalls
- Playbook `steps` is an ordered array; each step must declare a known `action`.
- Manual and scheduled triggers require explicit execution context.
- Approval decisions are irreversible; use comments for traceability.

---

## Appendix: Common HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200  | OK |
| 201  | Created |
| 204  | No Content |
| 400  | Bad Request |
| 401  | Unauthorized |
| 403  | Forbidden |
| 404  | Not Found |
| 422  | Unprocessable Entity |

---

*Document generated for LOGSOC-WEB backend compliance modules.*
