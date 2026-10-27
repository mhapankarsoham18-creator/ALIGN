"""
AIDDS Detector — Manifest schema and loader types.

Frozen at Phase 0 exit. See: docs/05_Role_Manifest_Spec.pdf
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ManifestLimits(BaseModel):
    """Rate and volume limits for a role."""

    max_records_per_call: int = Field(default=200, ge=1)
    max_bytes_out_per_hour: int = Field(default=5_000_000, ge=0)
    max_calls_per_minute: int = Field(default=60, ge=1)


class ApprovalRule(BaseModel):
    """An action that always requires human approval."""

    tool: str = Field(..., description="Tool name that triggers approval")
    when: str = Field(default="always", description="Condition expression, e.g. 'amount > 100000'")


class DelegationPolicy(BaseModel):
    """Which downstream roles this role may call and what scopes it may pass."""

    may_call: list[str] = Field(default_factory=list, description="Roles this role may delegate to")
    pass_scopes: list[str] = Field(
        default_factory=list,
        description="Tool scopes that may be passed to callees",
    )


class RoleManifest(BaseModel):
    """
    Declared role definition — the 'allowed' side of drift detection.

    12 fields as specified in the Role Manifest Spec.
    Manifests are YAML, versioned, and signed by the role owner.
    """

    role: str = Field(..., description="Unique role name, e.g. 'procurement-agent'")
    version: int = Field(..., ge=1, description="Integer version; increases on every change")
    owner: str = Field(..., description="Accountable person or team")
    description: str = Field(
        ...,
        description="One plain sentence of the role's purpose; also embedded for semantic drift",
    )
    allowed_tools: list[str] = Field(
        default_factory=list,
        description="Tools the role may call",
    )
    allowed_data_classes: list[str] = Field(
        default_factory=list,
        description="Data classes the role may access",
    )
    forbidden_data_classes: list[str] = Field(
        default_factory=list,
        description="Data classes the role must never access (forbidden wins)",
    )
    egress_allowlist: list[str] = Field(
        default_factory=list,
        description="Hosts the role may send data to; anything else is external egress",
    )
    limits: ManifestLimits = Field(
        default_factory=ManifestLimits,
        description="Rate and volume limits",
    )
    requires_approval: list[ApprovalRule] = Field(
        default_factory=list,
        description="Actions requiring human approval",
    )
    delegation: DelegationPolicy = Field(
        default_factory=DelegationPolicy,
        description="Delegation rules",
    )
    honeypots: list[str] = Field(
        default_factory=list,
        description="Decoy resources; any access = immediate alert",
    )
    signature: str = Field(
        default="",
        description="Ed25519 signature over canonical manifest, by owner's key",
    )
