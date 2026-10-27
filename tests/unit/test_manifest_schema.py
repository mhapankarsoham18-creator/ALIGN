"""
Unit tests for the AIDDS Manifest schema.

Validates all 12 fields, nested types, constraints, and YAML loading.
"""

from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from detector.schemas import (
    ApprovalRule,
    DelegationPolicy,
    ManifestLimits,
    RoleManifest,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_manifest(**overrides: object) -> RoleManifest:
    """Create a valid RoleManifest with sensible defaults."""
    defaults: dict[str, object] = {
        "role": "test-agent",
        "version": 1,
        "owner": "test-team",
        "description": "A test role for unit tests.",
        "allowed_tools": ["tool_a", "tool_b"],
        "allowed_data_classes": ["public"],
        "forbidden_data_classes": ["hr"],
        "egress_allowlist": ["internal.example.com"],
        "signature": "ed25519:test",
    }
    defaults.update(overrides)
    return RoleManifest(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# RoleManifest creation
# ---------------------------------------------------------------------------


class TestRoleManifest:
    """Tests for the RoleManifest Pydantic model."""

    def test_minimal_manifest(self) -> None:
        m = _make_manifest()
        assert m.role == "test-agent"
        assert m.version == 1

    def test_version_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            _make_manifest(version=0)

    def test_forbidden_data_classes_listed(self) -> None:
        m = _make_manifest(forbidden_data_classes=["hr", "payroll", "finance_ledger"])
        assert "hr" in m.forbidden_data_classes
        assert len(m.forbidden_data_classes) == 3

    def test_limits_defaults(self) -> None:
        m = _make_manifest()
        assert m.limits.max_records_per_call == 200
        assert m.limits.max_bytes_out_per_hour == 5_000_000
        assert m.limits.max_calls_per_minute == 60

    def test_custom_limits(self) -> None:
        m = _make_manifest(
            limits=ManifestLimits(
                max_records_per_call=50,
                max_bytes_out_per_hour=1_000_000,
                max_calls_per_minute=30,
            )
        )
        assert m.limits.max_records_per_call == 50

    def test_approval_rules_parse(self) -> None:
        rules = [ApprovalRule(tool="create_purchase_request", when="amount > 100000")]
        m = _make_manifest(requires_approval=rules)
        assert len(m.requires_approval) == 1
        assert m.requires_approval[0].tool == "create_purchase_request"

    def test_delegation_policy(self) -> None:
        delegation = DelegationPolicy(
            may_call=["pricing-analyst-agent"],
            pass_scopes=["read_catalog"],
        )
        m = _make_manifest(delegation=delegation)
        assert "pricing-analyst-agent" in m.delegation.may_call

    def test_honeypots_listed(self) -> None:
        m = _make_manifest(honeypots=["hr/salaries_2026_FULL.xlsx"])
        assert len(m.honeypots) == 1

    def test_manifest_round_trips_json(self) -> None:
        m = _make_manifest()
        json_str = m.model_dump_json()
        restored = RoleManifest.model_validate_json(json_str)
        assert restored.role == m.role
        assert restored.version == m.version

    def test_manifest_loads_from_yaml_dict(self) -> None:
        """Simulate loading a manifest from YAML (parsed to dict)."""
        yaml_str = """
role: procurement-agent
version: 3
owner: procurement-platform-team
description: Checks supplier prices and creates purchase requests.
allowed_tools: [supplier_price_api, read_catalog, create_purchase_request]
allowed_data_classes: [supplier, pricing, purchase_request]
forbidden_data_classes: [hr, payroll, finance_ledger]
egress_allowlist: [api.approved-supplier.com, erp.internal]
limits:
  max_records_per_call: 200
  max_bytes_out_per_hour: 5000000
  max_calls_per_minute: 60
requires_approval:
  - tool: create_purchase_request
    when: "amount > 100000"
delegation:
  may_call: [pricing-analyst-agent]
  pass_scopes: [read_catalog]
honeypots: [hr/salaries_2026_FULL.xlsx]
signature: "ed25519:placeholder"
"""
        data = yaml.safe_load(yaml_str)
        m = RoleManifest(**data)
        assert m.role == "procurement-agent"
        assert m.version == 3
        assert "hr" in m.forbidden_data_classes
        assert m.limits.max_records_per_call == 200
        assert len(m.requires_approval) == 1
        assert m.delegation.may_call == ["pricing-analyst-agent"]

    def test_manifest_from_actual_file(self) -> None:
        """Load the procurement-agent manifest file from disk."""
        import pathlib

        manifest_path = pathlib.Path("manifests/procurement-agent.yaml")
        if not manifest_path.exists():
            pytest.skip("Manifest file not found in CWD")
        with open(manifest_path) as f:
            data = yaml.safe_load(f)
        m = RoleManifest(**data)
        assert m.role == "procurement-agent"
        assert m.version >= 1
