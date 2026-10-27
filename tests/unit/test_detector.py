"""
Unit tests for the AIDDS Detector — engine, signals, and manifest loader.

Tests every signal checker individually and the full scoring pipeline
against representative attack and benign event sequences.
"""

from __future__ import annotations

import pathlib
import uuid
from datetime import UTC, datetime

import pytest

from detector.engine import score_event
from detector.manifest_loader import (
    _load_manifests_from_dir,
    get_manifest,
    reload_manifests,
)
from detector.schemas import RoleManifest
from detector.signals import (
    HONEYPOT_OVERRIDE_SCORE,
    KILL_CHAIN_OVERRIDE_SCORE,
    SessionState,
    SessionTracker,
    check_honeypot,
    check_kill_chain_override,
    check_misuse_pattern,
    check_role_violation,
    check_sensitivity,
    check_taint_flow,
    check_velocity,
    reset_tracker,
)
from gateway.schemas import Action, DataClass, TaintEntry, Tier, ToolCallEvent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(**overrides: object) -> ToolCallEvent:
    """Create a valid ToolCallEvent with sensible defaults."""
    defaults: dict[str, object] = {
        "agent_id": "test-agent-01",
        "role": "procurement-agent",
        "session_id": f"s-test-{uuid.uuid4().hex[:6]}",
        "tool": "read_catalog",
        "action": Action.READ,
        "resource": "catalog/prices.csv",
        "data_class": DataClass.PRICING,
        "sensitivity": 1,
        "manifest_version": 3,
        "token_id": "tok-test",
    }
    defaults.update(overrides)
    return ToolCallEvent(**defaults)  # type: ignore[arg-type]


def _make_manifest(**overrides: object) -> RoleManifest:
    """Create a test RoleManifest with typical procurement-agent settings."""
    defaults: dict[str, object] = {
        "role": "procurement-agent",
        "version": 3,
        "owner": "test-team",
        "description": "Checks supplier prices and creates purchase requests.",
        "allowed_tools": ["supplier_price_api", "read_catalog", "create_purchase_request"],
        "allowed_data_classes": ["supplier", "pricing", "purchase_request"],
        "forbidden_data_classes": ["hr", "payroll", "finance_ledger"],
        "egress_allowlist": ["api.approved-supplier.com", "erp.internal"],
        "honeypots": ["hr/salaries_2026_FULL.xlsx"],
    }
    defaults.update(overrides)
    return RoleManifest(**defaults)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _reset_session_tracker() -> None:
    """Reset the global session tracker before each test."""
    reset_tracker()


# ---------------------------------------------------------------------------
# Manifest loader tests
# ---------------------------------------------------------------------------


class TestManifestLoader:
    """Tests for manifest loading and lookup."""

    def test_load_manifests_from_disk(self) -> None:
        manifests_dir = pathlib.Path("manifests")
        manifests = _load_manifests_from_dir(manifests_dir)
        assert "procurement-agent" in manifests
        assert "support-agent" in manifests
        assert "hr-assistant-agent" in manifests

    def test_manifest_fields_parsed(self) -> None:
        manifests = _load_manifests_from_dir(pathlib.Path("manifests"))
        proc = manifests["procurement-agent"]
        assert proc.version == 3
        assert "supplier_price_api" in proc.allowed_tools
        assert "hr" in proc.forbidden_data_classes
        assert "hr/salaries_2026_FULL.xlsx" in proc.honeypots

    def test_get_manifest_returns_none_for_unknown(self) -> None:
        reload_manifests()
        result = get_manifest("nonexistent-role")
        assert result is None

    def test_empty_directory_returns_empty(self, tmp_path: pathlib.Path) -> None:
        manifests = _load_manifests_from_dir(tmp_path)
        assert manifests == {}


# ---------------------------------------------------------------------------
# Signal: role_violation
# ---------------------------------------------------------------------------


class TestRoleViolation:
    """Tests for the role_violation signal checker."""

    def test_in_role_tool_no_violation(self) -> None:
        manifest = _make_manifest()
        event = _make_event(tool="read_catalog", data_class=DataClass.PRICING)
        result = check_role_violation(event, manifest)
        assert result is None

    def test_forbidden_tool_fires(self) -> None:
        manifest = _make_manifest()
        event = _make_event(tool="hr_export_db", data_class=DataClass.HR)
        result = check_role_violation(event, manifest)
        assert result is not None
        assert result.signal == "role_violation"
        assert result.points > 0
        assert "hr_export_db" in result.text

    def test_forbidden_data_class_fires(self) -> None:
        manifest = _make_manifest()
        event = _make_event(
            tool="supplier_price_api",  # allowed tool
            data_class=DataClass.HR,  # forbidden data class
        )
        result = check_role_violation(event, manifest)
        assert result is not None
        assert "forbidden" in result.text

    def test_unapproved_destination_fires(self) -> None:
        manifest = _make_manifest()
        event = _make_event(
            tool="read_catalog",
            destination="unknown-host.example.com",
        )
        result = check_role_violation(event, manifest)
        assert result is not None
        assert "egress_allowlist" in result.text

    def test_approved_destination_no_violation(self) -> None:
        manifest = _make_manifest()
        event = _make_event(
            tool="supplier_price_api",
            destination="api.approved-supplier.com",
        )
        result = check_role_violation(event, manifest)
        assert result is None

    def test_no_manifest_fails_closed(self) -> None:
        """An unknown role has no manifest to authorise anything: it must score high."""
        event = _make_event()
        result = check_role_violation(event, None)
        assert result is not None
        assert result.points == 40
        assert "fail closed" in result.text

    def test_manifest_override_adds_tools(self) -> None:
        manifest = _make_manifest()
        event = _make_event(tool="supplier_rating_api", data_class=DataClass.SUPPLIER)
        # Without override: tool not allowed
        result = check_role_violation(event, manifest)
        assert result is not None

        # With override: tool becomes allowed
        overrides = {"added_tools": ["supplier_rating_api"]}
        result = check_role_violation(event, manifest, manifest_overrides=overrides)
        assert result is None

    def test_delegation_call_allowed_when_in_may_call(self) -> None:
        manifest = _make_manifest(
            delegation={"may_call": ["pricing-analyst-agent"], "pass_scopes": ["read_catalog"]}
        )
        event = _make_event(
            tool="delegate",
            action=Action.EXECUTE,
            resource="pricing-analyst-agent",
            data_class=DataClass.PRICING,
        )
        result = check_role_violation(event, manifest)
        assert result is None

    def test_delegation_chain_violation_fires(self) -> None:
        manifest = _make_manifest()
        event = _make_event(
            tool="hr_export_db",
            data_class=DataClass.HR,
            chain=["caller-bot", "callee-bot"],
        )
        result = check_role_violation(event, manifest)
        assert result is not None
        assert "delegated" in result.text.lower()


# ---------------------------------------------------------------------------
# Signal: taint_flow
# ---------------------------------------------------------------------------


class TestTaintFlow:
    """Tests for the taint_flow signal checker."""

    def test_no_taint_no_signal(self) -> None:
        manifest = _make_manifest()
        event = _make_event(taint=[])
        state = SessionState()
        result = check_taint_flow(event, manifest, state)
        assert result is None

    def test_taint_with_forbidden_data_fires(self) -> None:
        manifest = _make_manifest()
        taint = [TaintEntry(source="bad.pdf", ts=datetime.now(UTC), kind="document")]
        event = _make_event(
            tool="hr_export_db",
            data_class=DataClass.HR,
            taint=taint,
        )
        state = SessionState()
        result = check_taint_flow(event, manifest, state)
        assert result is not None
        assert result.signal == "taint_flow"
        assert result.points > 0

    def test_taint_in_role_no_signal(self) -> None:
        """B05 pattern: tainted but stays in-role — should NOT fire."""
        manifest = _make_manifest()
        taint = [TaintEntry(source="legit.pdf", ts=datetime.now(UTC), kind="document")]
        event = _make_event(
            tool="read_catalog",
            data_class=DataClass.PRICING,
            sensitivity=1,
            taint=taint,
        )
        state = SessionState()
        result = check_taint_flow(event, manifest, state)
        assert result is None

    def test_taint_with_external_egress_fires(self) -> None:
        manifest = _make_manifest()
        taint = [TaintEntry(source="bad.pdf", ts=datetime.now(UTC), kind="document")]
        event = _make_event(
            tool="http_post",
            action=Action.SEND,
            data_class=DataClass.HR,
            destination="unknown-host.example.com",
            taint=taint,
        )
        state = SessionState(forbidden_access_after_taint=True)
        result = check_taint_flow(event, manifest, state)
        assert result is not None
        assert "external" in result.text.lower() or "kill chain" in result.text.lower()

    def test_taint_to_allowed_destination_no_egress_signal(self) -> None:
        """Tainted context sending to an allowed host should not fire egress signal."""
        manifest = _make_manifest()
        taint = [TaintEntry(source="legit.pdf", ts=datetime.now(UTC), kind="document")]
        event = _make_event(
            tool="create_purchase_request",
            action=Action.WRITE,
            data_class=DataClass.PURCHASE_REQUEST,
            destination="erp.internal",
            taint=taint,
        )
        state = SessionState()
        result = check_taint_flow(event, manifest, state)
        assert result is None


# ---------------------------------------------------------------------------
# Signal: sensitivity
# ---------------------------------------------------------------------------


class TestSensitivity:
    """Tests for the sensitivity signal checker."""

    def test_allowed_data_no_signal(self) -> None:
        """In-role access to sensitive data should not fire."""
        manifest = _make_manifest()
        event = _make_event(data_class=DataClass.PRICING, sensitivity=2)
        result = check_sensitivity(event, manifest)
        assert result is None

    def test_forbidden_high_sensitivity_fires(self) -> None:
        manifest = _make_manifest()
        event = _make_event(data_class=DataClass.HR, sensitivity=3)
        result = check_sensitivity(event, manifest)
        assert result is not None
        assert result.signal == "sensitivity"
        assert result.points == 15

    def test_sensitivity_zero_no_signal(self) -> None:
        manifest = _make_manifest()
        event = _make_event(data_class=DataClass.UNKNOWN, sensitivity=0)
        result = check_sensitivity(event, manifest)
        assert result is None


# ---------------------------------------------------------------------------
# Signal: velocity
# ---------------------------------------------------------------------------


class TestVelocity:
    """Tests for the velocity signal checker."""

    def test_normal_session_no_signal(self) -> None:
        manifest = _make_manifest()
        event = _make_event()
        state = SessionState(out_of_scope_count=0)
        result = check_velocity(event, manifest, state)
        assert result is None

    def test_high_violation_count_fires(self) -> None:
        manifest = _make_manifest()
        event = _make_event()
        state = SessionState(out_of_scope_count=5)
        result = check_velocity(event, manifest, state)
        assert result is not None
        assert result.signal == "velocity"

    def test_excessive_bytes_fires(self) -> None:
        manifest = _make_manifest()
        event = _make_event(bytes_out=200_000)
        state = SessionState(total_bytes_out=6_000_000)  # above 5M limit
        result = check_velocity(event, manifest, state)
        assert result is not None
        assert "bytes" in result.text.lower()


# ---------------------------------------------------------------------------
# Signal: misuse_pattern
# ---------------------------------------------------------------------------


class TestMisusePattern:
    """Tests for the misuse_pattern signal checker."""

    def test_normal_call_no_signal(self) -> None:
        manifest = _make_manifest()
        event = _make_event(tool="read_catalog", data_class=DataClass.PRICING)
        state = SessionState()
        result = check_misuse_pattern(event, manifest, state)
        assert result is None

    def test_mimicry_allowed_tool_forbidden_data(self) -> None:
        """S06 pattern: allowed tool accessing forbidden data class."""
        manifest = _make_manifest()
        event = _make_event(
            tool="supplier_price_api",
            data_class=DataClass.HR,
            sensitivity=3,
        )
        state = SessionState()
        result = check_misuse_pattern(event, manifest, state)
        assert result is not None
        assert result.signal == "misuse_pattern"
        assert result.points == 30
        assert "mimicry" in result.text.lower()

    def test_agent_chain_exceeds_authority(self) -> None:
        """S08 pattern: delegated agent exceeds caller authority."""
        manifest = _make_manifest()
        event = _make_event(
            tool="hr_export_db",
            data_class=DataClass.HR,
            chain=["caller-agent", "callee-agent"],
        )
        state = SessionState()
        result = check_misuse_pattern(event, manifest, state)
        assert result is not None
        assert result.signal == "misuse_pattern"
        assert "delegated" in result.text.lower()

    def test_tainted_egress_unauthorized_tool(self) -> None:
        """S04 pattern: tainted agent using unauthorized tool to egress data."""
        manifest = _make_manifest()
        taint = [TaintEntry(source="poisoned_doc", ts=datetime.now(UTC), kind="tool_output")]
        event = _make_event(
            tool="http_post",
            action=Action.SEND,
            data_class=DataClass.CUSTOMER,
            bytes_out=125_000,
            taint=taint,
        )
        state = SessionState()
        result = check_misuse_pattern(event, manifest, state)
        assert result is not None
        assert result.signal == "misuse_pattern"
        assert "egress" in result.text.lower()


# ---------------------------------------------------------------------------
# Signal: honeypot
# ---------------------------------------------------------------------------


class TestHoneypot:
    """Tests for the honeypot signal checker."""

    def test_honeypot_access_fires(self) -> None:
        manifest = _make_manifest()
        event = _make_event(resource="hr/salaries_2026_FULL.xlsx")
        result = check_honeypot(event, manifest)
        assert result is not None
        assert result.signal == "honeypot"
        assert result.points == HONEYPOT_OVERRIDE_SCORE

    def test_normal_resource_no_signal(self) -> None:
        manifest = _make_manifest()
        event = _make_event(resource="catalog/prices.csv")
        result = check_honeypot(event, manifest)
        assert result is None


# ---------------------------------------------------------------------------
# Signal: kill_chain override
# ---------------------------------------------------------------------------


class TestKillChain:
    """Tests for the kill-chain override checker."""

    def test_complete_chain_fires(self) -> None:
        state = SessionState(
            taint_present=True,
            forbidden_access_after_taint=True,
            external_egress_after_taint=True,
        )
        result = check_kill_chain_override(state)
        assert result is not None
        assert result.points == KILL_CHAIN_OVERRIDE_SCORE

    def test_partial_chain_no_signal(self) -> None:
        state = SessionState(
            taint_present=True,
            forbidden_access_after_taint=True,
            external_egress_after_taint=False,  # missing egress
        )
        result = check_kill_chain_override(state)
        assert result is None

    def test_no_taint_no_chain(self) -> None:
        state = SessionState()
        result = check_kill_chain_override(state)
        assert result is None


# ---------------------------------------------------------------------------
# Session tracker
# ---------------------------------------------------------------------------


class TestSessionTracker:
    """Tests for the SessionTracker state accumulation."""

    def test_new_session_starts_clean(self) -> None:
        tracker = SessionTracker()
        state = tracker.get("s-new")
        assert state.events_seen == 0
        assert state.violation_count == 0

    def test_records_accumulate(self) -> None:
        manifest = _make_manifest()
        tracker = SessionTracker()
        session_id = "s-acc-test"

        event1 = _make_event(session_id=session_id, bytes_out=100)
        tracker.record(event1, manifest)

        event2 = _make_event(session_id=session_id, bytes_out=200)
        tracker.record(event2, manifest)

        state = tracker.get(session_id)
        assert state.events_seen == 2
        assert state.total_bytes_out == 300

    def test_taint_tracking(self) -> None:
        manifest = _make_manifest()
        tracker = SessionTracker()
        session_id = "s-taint-test"
        taint = [TaintEntry(source="bad.pdf", ts=datetime.now(UTC), kind="document")]

        event = _make_event(
            session_id=session_id,
            data_class=DataClass.HR,
            taint=taint,
        )
        state = tracker.record(event, manifest)
        assert state.taint_present is True
        assert state.forbidden_access_after_taint is True


# ---------------------------------------------------------------------------
# Full engine: score_event
# ---------------------------------------------------------------------------


class TestScoreEvent:
    """Integration tests for the full scoring pipeline."""

    def test_normal_procurement_observe(self) -> None:
        """Normal in-role procurement event → observe (score < 40)."""
        reload_manifests()
        event = _make_event(
            tool="read_catalog",
            data_class=DataClass.PRICING,
            sensitivity=1,
        )
        decision = score_event(event)
        assert decision.tier == Tier.OBSERVE
        assert decision.score < 40

    def test_forbidden_data_class_high_score(self) -> None:
        """Accessing forbidden data class → high score."""
        reload_manifests()
        event = _make_event(
            tool="hr_export_db",
            data_class=DataClass.HR,
            sensitivity=3,
        )
        decision = score_event(event)
        assert decision.score >= 40
        assert decision.tier in (Tier.STEP_UP, Tier.RESTRICT, Tier.ISOLATE)

    def test_honeypot_triggers_isolate(self) -> None:
        """Accessing a honeypot resource → score ≥ 95, tier = isolate."""
        reload_manifests()
        event = _make_event(
            resource="hr/salaries_2026_FULL.xlsx",
            data_class=DataClass.HR,
            sensitivity=3,
        )
        decision = score_event(event)
        assert decision.score >= 95
        assert decision.tier == Tier.ISOLATE

    def test_full_kill_chain_isolate(self) -> None:
        """Full kill chain (S01 pattern) → score ≥ 90, tier = isolate."""
        reload_manifests()
        session_id = f"s-kill-{uuid.uuid4().hex[:4]}"
        taint = [TaintEntry(source="bad.pdf", ts=datetime.now(UTC), kind="document")]

        # 1. Normal warmup
        score_event(_make_event(session_id=session_id))

        # 2. Tainted read
        score_event(
            _make_event(
                session_id=session_id,
                tool="supplier_price_api",
                resource="bad.pdf",
                taint=taint,
            )
        )

        # 3. Forbidden access after taint
        score_event(
            _make_event(
                session_id=session_id,
                tool="hr_export_db",
                data_class=DataClass.HR,
                sensitivity=3,
                taint=taint,
            )
        )

        # 4. External egress — this is the kill chain completion
        decision = score_event(
            _make_event(
                session_id=session_id,
                tool="http_post",
                action=Action.SEND,
                data_class=DataClass.HR,
                sensitivity=3,
                destination="unknown-host.example.com",
                bytes_out=48200,
                taint=taint,
            )
        )

        assert decision.score >= 90
        assert decision.tier == Tier.ISOLATE

    def test_benign_tainted_session_stays_low(self) -> None:
        """B05 pattern: taint present but agent stays in-role → observe."""
        reload_manifests()
        session_id = f"s-b05-{uuid.uuid4().hex[:4]}"
        taint = [TaintEntry(source="legit.pdf", ts=datetime.now(UTC), kind="document")]

        # 1. Read untrusted PDF
        d1 = score_event(
            _make_event(
                session_id=session_id,
                tool="supplier_price_api",
                resource="legit.pdf",
                data_class=DataClass.SUPPLIER,
                taint=taint,
            )
        )

        # 2. Normal in-role work (still tainted)
        d2 = score_event(
            _make_event(
                session_id=session_id,
                tool="read_catalog",
                data_class=DataClass.PRICING,
                taint=taint,
            )
        )

        # 3. Write to allowed destination (still tainted)
        d3 = score_event(
            _make_event(
                session_id=session_id,
                tool="create_purchase_request",
                action=Action.WRITE,
                data_class=DataClass.PURCHASE_REQUEST,
                destination="erp.internal",
                bytes_out=800,
                taint=taint,
            )
        )

        for d in [d1, d2, d3]:
            assert d.tier == Tier.OBSERVE
            assert d.score < 40

    def test_alert_id_generated_for_high_score(self) -> None:
        """Actionable events get an alert_id; observe events don't."""
        reload_manifests()

        # Low score
        low = score_event(_make_event())
        assert low.alert_id is None

        # High score
        high = score_event(
            _make_event(
                tool="hr_export_db",
                data_class=DataClass.HR,
                sensitivity=3,
            )
        )
        assert high.alert_id is not None
        assert high.alert_id.startswith("A-")

    def test_reasons_sorted_by_points(self) -> None:
        """Reasons should be sorted highest-points-first."""
        reload_manifests()
        decision = score_event(
            _make_event(
                tool="hr_export_db",
                data_class=DataClass.HR,
                sensitivity=3,
            )
        )
        if len(decision.reasons) >= 2:
            assert decision.reasons[0].points >= decision.reasons[1].points
