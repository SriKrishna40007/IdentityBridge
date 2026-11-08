from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

PrivilegedRole = Literal[
    "identity-admin",
    "security-analyst",
    "auditor",
]


class PrivilegeRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_user_id: str = Field(min_length=1, max_length=255)
    role: PrivilegedRole
    justification: str = Field(min_length=20, max_length=2000)
    duration_minutes: int = Field(default=60, ge=1, le=480)


class PrivilegeDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comment: str | None = Field(default=None, max_length=1000)


class PrivilegeRequestRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    requester_sub: str
    target_user_id: str
    role_name: str
    status: str
    approver_sub: str | None
    decision_comment: str | None
    requested_duration_minutes: int
    requested_at: datetime
    approved_at: datetime | None
    activated_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
