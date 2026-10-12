# app/schemas_soar.py — T92
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_type: str = "manual"
    trigger_conditions: Optional[str] = None
    steps: str
    created_by: int = 0


class PlaybookUpdate(BaseModel):
    description: Optional[str] = None
    trigger_conditions: Optional[str] = None
    steps: Optional[str] = None
    is_active: Optional[bool] = None


class ExecuteRequest(BaseModel):
    playbook_id: int
    trigger_type: str = "manual"
    trigger_entity_id: Optional[int] = None
    trigger_entity_type: str = ""
    triggered_by: int = 0


class ApprovalDecision(BaseModel):
    decision: str
    approver_user_id: int = 0


class IntegrationCreate(BaseModel):
    name: str
    integration_type: str = "custom"
    base_url: str = ""
    api_key: str = ""
    auth_type: str = "bearer"
    supported_actions: Optional[str] = None


class PlaybookResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    trigger_type: str
    is_active: bool
    version: int
    class Config:
        from_attributes = True


class ExecutionResponse(BaseModel):
    id: int
    playbook_id: int
    trigger_type: str
    status: str
    current_step: int
    result_summary: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: int
    class Config:
        from_attributes = True


class ApprovalResponse(BaseModel):
    id: int
    execution_id: int
    step_number: int
    status: str
    approver_role: str
    class Config:
        from_attributes = True


class IntegrationResponse(BaseModel):
    id: int
    name: str
    integration_type: str
    base_url: str
    is_active: bool
    last_test_result: str
    class Config:
        from_attributes = True