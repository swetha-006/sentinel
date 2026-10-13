from __future__ import annotations
from enum import StrEnum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

class Tier(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class DecisionKind(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_HUMAN = "needs_human"

class Decision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    decision: DecisionKind
    reason_code: str
    inputs_hash: str

class Finding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    advisory_id: str
    package: str
    repository: str
    change_type: str = "unknown"
    paths: tuple[str, ...] = ()
    severity: str = "unknown"
    advisory_text: str = ""

class SLOMetrics(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    error_rate: float = Field(ge=0, le=1)
    p95_latency_regression: float = Field(ge=-1)
    observed_minutes: int = Field(ge=0)

class ScanResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    scanner: str
    status: str
    report_digest: str

class Approval(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    actor: str
    stage: str
    approved: bool
    timestamp: str

class ProofReceipt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: int = 1
    correlation_id: str
    idempotency_key: str
    finding: dict[str, Any]
    autonomy_tier: Tier
    proof: dict[str, Any]
    scans: tuple[ScanResult, ...]
    approvals: tuple[Approval, ...]
    canary: dict[str, Any]
    decision: Decision
    signed_off_by: str
    signature: str
