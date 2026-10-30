# app/schemas_aiact.py — T91
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date


class AiSystemCreate(BaseModel):
    name: str
    provider: str
    provider_contact: str = ""
    version: str = ""
    purpose: str
    use_case: Optional[str] = None
    data_categories: Optional[str] = None
    has_personal_data: bool = False
    has_sensitive_data: bool = False
    entity_role: str = "deployer"
    is_registered_eu: bool = False
    created_by: int = 0


class AiClassificationCreate(BaseModel):
    ai_system_id: int
    is_safety_component: bool = False
    is_in_regulated_product: bool = False
    used_critical_infrastructure: bool = False
    used_education: bool = False
    used_employment: bool = False
    used_essential_services: bool = False
    used_law_enforcement: bool = False
    used_migration: bool = False
    used_justice: bool = False
    used_democracy: bool = False
    uses_subliminal: bool = False
    uses_vulnerability_exploitation: bool = False
    uses_social_scoring: bool = False
    uses_criminal_prediction: bool = False
    uses_facial_scraping: bool = False
    uses_realtime_biometric: bool = False
    uses_emotion_inference: bool = False
    uses_biocategorization: bool = False
    uses_untargeted_surveillance: bool = False
    interacts_with_humans: bool = False
    generates_content: bool = False
    uses_emotion_recognition: bool = False
    uses_biometric_categorization: bool = False
    classified_by: int = 0


class AiIncidentCreate(BaseModel):
    ai_system_id: int
    case_id: Optional[int] = None
    incident_description: str
    incident_date: datetime
    authority_name: str = ""
    created_by: int = 0


class AiIncidentUpdate(BaseModel):
    provider_notified: Optional[bool] = None
    authority_notified: Optional[bool] = None
    measures_taken: Optional[str] = None
    system_suspended: Optional[bool] = None
    regulatory_notification_id: Optional[int] = None


class AiTransparencyUpdate(BaseModel):
    interaction_notice_displayed: Optional[bool] = None
    interaction_notice_text: Optional[str] = None
    content_marking_active: Optional[bool] = None
    marking_method: Optional[str] = None
    emotion_recognition_disclosed: Optional[bool] = None
    biometric_categorization_disclosed: Optional[bool] = None
    high_risk_persons_informed: Optional[bool] = None
    verified_by: int = 0


class AiSystemResponse(BaseModel):
    id: int
    name: str
    provider: str
    version: str
    purpose: str
    entity_role: str
    risk_level: str
    status: str
    class Config:
        from_attributes = True


class AiClassificationResponse(BaseModel):
    id: int
    ai_system_id: int
    risk_level: str
    rationale: Optional[str] = None
    transparency_required: bool
    class Config:
        from_attributes = True


class AiIncidentResponse(BaseModel):
    id: int
    ai_system_id: int
    incident_description: str
    provider_notified: bool
    authority_notified: bool
    system_suspended: bool
    class Config:
        from_attributes = True


class AiTransparencyResponse(BaseModel):
    id: int
    ai_system_id: int
    interaction_notice_displayed: bool
    content_marking_active: bool
    class Config:
        from_attributes = True