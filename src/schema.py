"""Pydantic request/response models. Strict validation at the trust boundary."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, StrictBool, field_validator

MAX_CODE_BYTES = 102_400  # 100 KB hard cap

Severity = Literal["critical", "high", "medium", "low"]
Confidence = Literal["high", "medium", "low"]
Decision = Literal["ALLOW", "REVIEW", "BLOCK"]
PolicyProfile = Literal["agent_default", "strict", "lenient"]
Language = Literal["python", "javascript", "typescript", "tsx"]


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    category: str
    line_start: int
    line_end: int
    column_start: int
    message: str
    evidence: str
    confidence: Confidence
    remediation: str


class Summary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class Limits(BaseModel):
    code_bytes: int
    maximum_code_bytes: int = MAX_CODE_BYTES


class PreflightRequest(BaseModel):
    request_id: str = Field(..., min_length=1, max_length=200)
    source_code: str = Field(..., min_length=0)
    language: Language = "python"
    policy_profile: PolicyProfile = "agent_default"
    explain: StrictBool = False

    @field_validator("source_code")
    @classmethod
    def _size_and_encoding(cls, v: str) -> str:
        # str is already valid unicode; enforce the UTF-8 byte budget.
        if len(v.encode("utf-8")) > MAX_CODE_BYTES:
            raise ValueError(f"source_code exceeds {MAX_CODE_BYTES} bytes")
        return v


class Explanation(BaseModel):
    model: str
    input_tokens: int
    output_tokens: int
    provider_cost_usd_micros: int
    text: str
    fell_back: bool = False


class Assurance(BaseModel):
    analysis_kind: Literal["deterministic_static_analysis"] = "deterministic_static_analysis"
    syntax_tree_complete: bool
    checked: list[str]
    not_checked: list[str]
    disclaimer: str


class ReportSignature(BaseModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str
    canonicalization: Literal["agent-preflight-json-v1"] = "agent-preflight-json-v1"
    payload_sha256: str
    signature_base64url: str


class PreflightResponse(BaseModel):
    request_id: str
    decision: Decision
    source_sha256: str
    ruleset_version: str
    engine_version: str
    findings: list[Finding]
    summary: Summary
    limits: Limits
    scan_duration_ms: int
    charged: bool
    payment_environment: str
    timestamp: str
    assurance: Assurance
    idempotent_replay: bool = False
    explanation: Explanation | None = None
    signature: ReportSignature | None = None


# ---------------------------------------------------------------------------
# Tool Quality Scoring — pre-execution intent scoring for AI agent tool calls
# ---------------------------------------------------------------------------

ToolDecision = Literal["SAFE", "CAUTION", "DANGER"]


class ToolCallRequest(BaseModel):
    request_id: str = Field(..., min_length=1, max_length=200)
    tool_name: str = Field(..., min_length=1, max_length=200)
    tool_args: dict = Field(default_factory=dict)
    context: dict | None = Field(default=None)


class DimensionScore(BaseModel):
    rule_id: str
    score: float = Field(..., ge=0.0, le=1.0)
    finding: str


class ToolScoreResponse(BaseModel):
    request_id: str
    decision: ToolDecision
    score: float = Field(..., ge=0.0, le=1.0)
    dimensions: dict[str, DimensionScore]
    recommendation: str
    timestamp: str
    assurance: Assurance
    idempotent_replay: bool = False
    charged: bool = False
    payment_environment: str = "disabled"
    signature: ReportSignature | None = None
