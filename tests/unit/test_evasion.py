"""
Unit tests for AIDDS Evasion Resistance (Phase 7 Hardening).

Tests adversary evasion attempts:
1. Honeypot path traversal (../, ..\\)
2. Honeypot path casing (HR/SALARIES_2026_FULL.XLSX)
3. Honeypot path separators (\\ vs /)
4. Egress allowlist bypass via scheme, port, case, trailing dot
5. Micro-batched exfiltration across multiple events
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from detector.engine import score_event
from detector.manifest_loader import get_manifest
from detector.signals import (
    SessionTracker,
    _normalize_destination,
    _normalize_resource,
    check_honeypot,
    check_role_violation,
    check_velocity,
)
from gateway.schemas import Action, DataClass, DecisionVerb, Tier, ToolCallEvent


def make_event(
    role: str = "support-agent",
    tool: str = "ticket_system",
    data_class: DataClass = DataClass.TICKET,
    resource: str = "ticket/123",
    destination: str | None = None,
    bytes_out: int = 100,
    session_id: str = "evasion_sess_1",
) -> ToolCallEvent:
    return ToolCallEvent(
        event_id=uuid.uuid4(),
        token_id="tok-test",
        timestamp=datetime.now(UTC),
        agent_id="test_agent",
        session_id=session_id,
        role=role,
        manifest_version=1,
        tool=tool,
        action=Action.READ,
        resource=resource,
        data_class=data_class,
        sensitivity=1,
        bytes_out=bytes_out,
        destination=destination,
    )


class TestEvasionNormalizationHelpers:
    """Test unit normalization functions against tricky input strings."""

    def test_normalize_resource_path_traversal(self) -> None:
        assert (
            _normalize_resource("hr/../hr/salaries_2026_FULL.xlsx") == "hr/salaries_2026_full.xlsx"
        )
        assert _normalize_resource("/hr/salaries_2026_FULL.xlsx") == "hr/salaries_2026_full.xlsx"
        assert (
            _normalize_resource("finance/../../hr/salaries_2026_FULL.xlsx")
            == "hr/salaries_2026_full.xlsx"
        )

    def test_normalize_resource_backslashes(self) -> None:
        assert _normalize_resource(r"hr\salaries_2026_FULL.xlsx") == "hr/salaries_2026_full.xlsx"
        assert _normalize_resource(r"\hr\salaries_2026_FULL.xlsx") == "hr/salaries_2026_full.xlsx"

    def test_normalize_destination_variations(self) -> None:
        assert _normalize_destination("HTTPS://API.EXIF-DROP.COM/") == "api.exif-drop.com"
        assert _normalize_destination("http://api.exif-drop.com:443/upload") == "api.exif-drop.com"
        # user-info trick: the real host is what follows the last '@'
        assert _normalize_destination("https://api.ok.com@evil.io/x") == "evil.io"
        assert _normalize_destination("https://evil.io@api.ok.com/x") == "api.ok.com"
        assert _normalize_destination("API.EXIF-DROP.COM.") == "api.exif-drop.com"
        assert _normalize_destination("https://api.github.com/repos") == "api.github.com"


class TestHoneypotEvasionResistance:
    """Verify that honeypots cannot be evaded using traversal or casing."""

    def test_honeypot_exact_match(self) -> None:
        manifest = get_manifest("procurement-agent")
        event = make_event(
            role="procurement-agent",
            resource="hr/salaries_2026_FULL.xlsx",
        )
        reason = check_honeypot(event, manifest)
        assert reason is not None
        assert reason.points == 95

    def test_honeypot_traversal_evasion_blocked(self) -> None:
        manifest = get_manifest("procurement-agent")
        event = make_event(
            role="procurement-agent",
            resource="finance/../hr/salaries_2026_FULL.xlsx",
        )
        reason = check_honeypot(event, manifest)
        assert reason is not None
        assert reason.points == 95

    def test_honeypot_case_evasion_blocked(self) -> None:
        manifest = get_manifest("procurement-agent")
        event = make_event(
            role="procurement-agent",
            resource="HR/SALARIES_2026_FULL.XLSX",
        )
        reason = check_honeypot(event, manifest)
        assert reason is not None
        assert reason.points == 95

    def test_honeypot_windows_separator_evasion_blocked(self) -> None:
        manifest = get_manifest("procurement-agent")
        event = make_event(
            role="procurement-agent",
            resource=r"hr\salaries_2026_FULL.xlsx",
        )
        reason = check_honeypot(event, manifest)
        assert reason is not None
        assert reason.points == 95

    def test_honeypot_full_engine_isolation(self) -> None:
        event = make_event(
            role="procurement-agent",
            resource="internal/../hr/salaries_2026_FULL.xlsx",
        )
        decision = score_event(event)
        assert decision.tier == Tier.ISOLATE
        assert decision.decision == DecisionVerb.DENY
        assert decision.score >= 95


class TestEgressEvasionResistance:
    """Verify that unauthorized egress cannot evade detection with case or scheme tricks."""

    def test_egress_casing_and_scheme_detected(self) -> None:
        manifest = get_manifest("support-agent")
        event = make_event(
            role="support-agent",
            destination="HTTPS://EVIL-EXFILTRATION-DROP.NET/COLLECT",
        )
        reason = check_role_violation(event, manifest)
        assert reason is not None
        assert "not in egress_allowlist" in reason.text

    def test_egress_allowlisted_host_with_scheme_allowed(self) -> None:
        manifest = get_manifest("support-agent")
        event = make_event(
            role="support-agent",
            destination="https://helpdesk.internal.",
        )
        reason = check_role_violation(event, manifest)
        assert reason is None or "not in egress_allowlist" not in reason.text


class TestMicroBatchedExfiltrationResistance:
    """Verify velocity detection catches slow micro-batched exfiltration."""

    def test_micro_batch_accumulates_and_triggers_velocity(self) -> None:
        tracker = SessionTracker()
        manifest = get_manifest("support-agent")
        sess_id = "micro_batch_sess"

        reason = None
        for _ in range(5):
            event = make_event(
                role="support-agent",
                bytes_out=25_000,
                session_id=sess_id,
            )
            state = tracker.record(event, manifest)
            reason = check_velocity(event, manifest, state)

        assert reason is not None
        assert "micro-batched exfiltration" in reason.text
