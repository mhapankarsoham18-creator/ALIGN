"""
AIDDS Gateway — Event, Decision, and shared schemas (v1).

Frozen at Phase 0 exit. Changes require a version bump (v1 → v2).
See: docs/04_Event_Schema_and_API_Spec.pdf
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Action(enum.StrEnum):
    """The type of operation the agent performed."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SEND = "send"
    EXECUTE = "execute"


class DataClass(enum.StrEnum):
    """Sensitivity classification of the data touched."""

    SUPPLIER = "supplier"
    PRICING = "pricing"
    PURCHASE_REQUEST = "purchase_request"
    HR = "hr"
    PAYROLL = "payroll"
    FINANCE = "finance"
    FINANCE_LEDGER = "finance_ledger"
    PUBLIC = "public"
    UNKNOWN = "unknown"
    # Agent-support related
    TICKET = "ticket"
    KNOWLEDGE_BASE = "knowledge_base"
    CUSTOMER = "customer"
    LEAVE_POLICY = "leave_policy"
    ORG_CHART = "org_chart"
    ONBOARDING = "onboarding"


class DecisionVerb(enum.StrEnum):
    """What the gateway should do with the tool call."""

    ALLOW = "allow"
    STEP_UP = "step_up"
    RESTRICT = "restrict"
    DENY = "deny"


class Tier(enum.StrEnum):
    """Graduated response tier."""

    OBSERVE = "observe"  # 0-39
    STEP_UP = "step_up"  # 40-69
    RESTRICT = "restrict"  # 70-89
    ISOLATE = "isolate"  # 90-100


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class TaintEntry(BaseModel):
    """Tracks untrusted content the agent has read in this session."""

    source: str = Field(
        ...,
        max_length=512,
        description="Origin of untrusted content, e.g. 'supplier_invoice.pdf'",
    )
    ts: datetime = Field(..., description="When the tainted content was read (ISO 8601 UTC)")
    kind: str = Field(
        ...,
        max_length=64,
        description="Type of source: document, web, tool_output, email, etc.",
    )


class Reason(BaseModel):
    """One contributing signal to the risk score, shown to the analyst."""

    signal: str = Field(
        ..., description="Signal name, e.g. role_violation, taint_flow, sensitivity"
    )
    points: int = Field(..., ge=0, le=100, description="Points contributed to the total score")
    text: str = Field(..., description="Plain-language explanation for the analyst")


# ---------------------------------------------------------------------------
# Event schema v1 — 16 fields
# ---------------------------------------------------------------------------


class ToolCallEvent(BaseModel):
    """
    One tool call by an agent, as logged by the gateway.

    This is the universal event format used by every AIDDS component.
    Frozen at Phase 0; changes require a schema version bump.
    """

    event_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Unique identifier per tool call",
    )
    ts: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Time the call was received (ISO 8601 UTC)",
    )
    agent_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Stable agent identity (the credential owner)",
    )
    role: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Declared role, matches a manifest name",
    )
    session_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="One run of the agent; isolation applies at this level",
    )
    tool: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Tool or API called",
    )
    action: Action = Field(
        ...,
        description="Type of operation: read, write, delete, send, execute",
    )
    resource: str = Field(
        ...,
        max_length=512,
        description="Path, URL or record identifier touched",
    )
    data_class: DataClass = Field(
        default=DataClass.UNKNOWN,
        description="Sensitivity classification of the data touched",
    )
    sensitivity: int = Field(
        default=0,
        ge=0,
        le=3,
        description="0=public, 1=internal, 2=confidential, 3=restricted",
    )
    destination: str | None = Field(
        default=None,
        max_length=256,
        description="Host for outbound calls; null for internal reads",
    )
    bytes_out: int = Field(
        default=0,
        ge=0,
        le=10**12,
        description="Payload size sent out in bytes",
    )
    taint: list[TaintEntry] = Field(
        default_factory=list,
        max_length=50,
        description="Untrusted sources the context has read",
    )
    chain: list[str] = Field(
        default_factory=list,
        max_length=16,
        description="Delegation chain, caller first: [agent_A, agent_B]",
    )
    manifest_version: int = Field(
        ...,
        ge=1,
        le=10**6,
        description="Manifest version in force at call time",
    )
    token_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Token identifier (never the token itself)",
    )


# ---------------------------------------------------------------------------
# Decision schema — returned to the gateway by the detector
# ---------------------------------------------------------------------------


class Decision(BaseModel):
    """
    The detector's verdict on a single tool-call event.

    Includes the risk score, graduated tier, human-readable reasons,
    and an optional alert ID for the dashboard.
    """

    event_id: uuid.UUID = Field(..., description="Matches the originating ToolCallEvent")
    decision: DecisionVerb = Field(..., description="Gateway enforcement action")
    score: int = Field(..., ge=0, le=100, description="Composite risk score")
    tier: Tier = Field(..., description="Graduated response tier")
    reasons: list[Reason] = Field(
        default_factory=list,
        description="Top contributing signals with points and explanations",
    )
    alert_id: str | None = Field(
        default=None,
        description="Alert identifier when score >= 40; null for observe tier",
    )
