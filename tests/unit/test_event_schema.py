"""
Unit tests for the AIDDS Event schema (v1).

Validates all 16 fields, enums, defaults, constraints, and serialisation.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from gateway.schemas import (
    Action,
    DataClass,
    Decision,
    DecisionVerb,
    Reason,
    TaintEntry,
    Tier,
    ToolCallEvent,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(**overrides: object) -> ToolCallEvent:
    """Create a valid ToolCallEvent with sensible defaults, then apply overrides."""
    defaults: dict[str, object] = {
        "agent_id": "test-agent-01",
        "role": "procurement-agent",
        "session_id": "s-001",
        "tool": "read_catalog",
        "action": Action.READ,
        "resource": "catalog/prices.csv",
        "manifest_version": 3,
        "token_id": "tok-001",
    }
    defaults.update(overrides)
    return ToolCallEvent(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Event creation
# ---------------------------------------------------------------------------


class TestToolCallEvent:
    """Tests for the ToolCallEvent Pydantic model."""

    def test_minimal_event_creates_successfully(self) -> None:
        event = _make_event()
        assert event.agent_id == "test-agent-01"
        assert event.role == "procurement-agent"
        assert isinstance(event.event_id, uuid.UUID)
        assert isinstance(event.ts, datetime)

    def test_defaults_are_applied(self) -> None:
        event = _make_event()
        assert event.data_class == DataClass.UNKNOWN
        assert event.sensitivity == 0
        assert event.destination is None
        assert event.bytes_out == 0
        assert event.taint == []
        assert event.chain == []

    def test_all_action_enums_are_valid(self) -> None:
        for action in Action:
            event = _make_event(action=action)
            assert event.action == action

    def test_all_data_class_enums_are_valid(self) -> None:
        for dc in DataClass:
            event = _make_event(data_class=dc)
            assert event.data_class == dc

    def test_sensitivity_range_valid(self) -> None:
        for s in range(4):
            event = _make_event(sensitivity=s)
            assert event.sensitivity == s

    def test_sensitivity_out_of_range_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _make_event(sensitivity=4)
        with pytest.raises(ValidationError):
            _make_event(sensitivity=-1)

    def test_taint_entries_parse(self) -> None:
        taint = [
            TaintEntry(
                source="supplier_invoice.pdf",
                ts=datetime(2026, 10, 23, 8, 9, 2, tzinfo=UTC),
                kind="document",
            )
        ]
        event = _make_event(taint=taint)
        assert len(event.taint) == 1
        assert event.taint[0].source == "supplier_invoice.pdf"

    def test_chain_parses(self) -> None:
        event = _make_event(chain=["agent_A", "agent_B"])
        assert event.chain == ["agent_A", "agent_B"]

    def test_destination_can_be_set(self) -> None:
        event = _make_event(destination="unknown-host.example.com", bytes_out=1024)
        assert event.destination == "unknown-host.example.com"
        assert event.bytes_out == 1024

    def test_event_serialises_to_dict(self) -> None:
        event = _make_event()
        d = event.model_dump()
        assert "event_id" in d
        assert "ts" in d
        assert d["agent_id"] == "test-agent-01"

    def test_event_round_trips_through_json(self) -> None:
        event = _make_event()
        json_str = event.model_dump_json()
        restored = ToolCallEvent.model_validate_json(json_str)
        assert restored.event_id == event.event_id
        assert restored.agent_id == event.agent_id

    def test_missing_required_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            ToolCallEvent(agent_id="x")  # type: ignore[call-arg]

    def test_manifest_version_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            _make_event(manifest_version=0)

    def test_bytes_out_cannot_be_negative(self) -> None:
        with pytest.raises(ValidationError):
            _make_event(bytes_out=-1)


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


class TestDecision:
    """Tests for the Decision response model."""

    def test_minimal_decision(self) -> None:
        d = Decision(
            event_id=uuid.uuid4(),
            decision=DecisionVerb.ALLOW,
            score=0,
            tier=Tier.OBSERVE,
        )
        assert d.score == 0
        assert d.alert_id is None

    def test_decision_with_reasons(self) -> None:
        reasons = [
            Reason(signal="role_violation", points=35, text="hr data not allowed"),
            Reason(signal="taint_flow", points=25, text="after untrusted PDF read"),
        ]
        d = Decision(
            event_id=uuid.uuid4(),
            decision=DecisionVerb.DENY,
            score=91,
            tier=Tier.ISOLATE,
            reasons=reasons,
            alert_id="A-9421",
        )
        assert d.score == 91
        assert len(d.reasons) == 2
        assert d.reasons[0].points == 35

    def test_score_out_of_range_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Decision(
                event_id=uuid.uuid4(),
                decision=DecisionVerb.ALLOW,
                score=101,
                tier=Tier.OBSERVE,
            )

    def test_all_tiers(self) -> None:
        for tier in Tier:
            d = Decision(
                event_id=uuid.uuid4(),
                decision=DecisionVerb.ALLOW,
                score=0,
                tier=tier,
            )
            assert d.tier == tier

    def test_all_decision_verbs(self) -> None:
        for verb in DecisionVerb:
            d = Decision(
                event_id=uuid.uuid4(),
                decision=verb,
                score=50,
                tier=Tier.STEP_UP,
            )
            assert d.decision == verb
