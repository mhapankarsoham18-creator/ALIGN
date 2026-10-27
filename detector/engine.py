"""
AIDDS Detector — Risk engine.

Scores each ToolCallEvent by running all signal checkers, aggregating points (each signal is
capped at its own weight), applying hard overrides (honeypot, kill chain), mapping the total
to a graduated tier, and returning a Decision with human-readable reasons.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Collection

from detector.baseline import START, BaselineStore, get_baselines
from detector.manifest_loader import get_manifest
from detector.signals import (
    HONEYPOT_OVERRIDE_SCORE,
    KILL_CHAIN_OVERRIDE_SCORE,
    WEIGHT_CUMULATIVE_DRIFT,
    WEIGHT_DISTRIBUTION_DRIFT,
    WEIGHT_IDENTITY_MISMATCH,
    WEIGHT_MISUSE,
    WEIGHT_ROLE_VIOLATION,
    WEIGHT_SEMANTIC_DRIFT,
    WEIGHT_SENSITIVITY,
    WEIGHT_SEQUENCE_RARITY,
    WEIGHT_TAINT_FLOW,
    WEIGHT_VELOCITY,
    SessionTracker,
    _taint_of,
    check_cumulative_drift,
    check_distribution_drift,
    check_honeypot,
    check_kill_chain_override,
    check_misuse_pattern,
    check_role_violation,
    check_sensitivity,
    check_sequence_rarity,
    check_taint_flow,
    check_velocity,
    get_tracker,
    update_cusum,
)
from gateway.config import settings
from gateway.schemas import Decision, DecisionVerb, Reason, Tier, ToolCallEvent

# ---------------------------------------------------------------------------
# Signals and their caps.  The final score is the sum of the (capped) signal points,
# limited to 100, then raised to the override floor if the honeypot / kill chain fired.
# ---------------------------------------------------------------------------

SIGNAL_CAPS: dict[str, int] = {
    "role_violation": WEIGHT_ROLE_VIOLATION,
    "taint_flow": WEIGHT_TAINT_FLOW,
    "sensitivity": WEIGHT_SENSITIVITY,
    "misuse_pattern": WEIGHT_MISUSE,
    "velocity": WEIGHT_VELOCITY,
    "sequence_rarity": WEIGHT_SEQUENCE_RARITY,
    "distribution_drift": WEIGHT_DISTRIBUTION_DRIFT,
    "cumulative_drift": WEIGHT_CUMULATIVE_DRIFT,
    "semantic_drift": WEIGHT_SEMANTIC_DRIFT,
    "identity_mismatch": WEIGHT_IDENTITY_MISMATCH,
    "honeypot": HONEYPOT_OVERRIDE_SCORE,
    "kill_chain": KILL_CHAIN_OVERRIDE_SCORE,
}

# Signals that count as "anomalous behaviour" when updating the CUSUM accumulator
_ANOMALY_SIGNALS = (
    "role_violation",
    "misuse_pattern",
    "sensitivity",
    "sequence_rarity",
    "distribution_drift",
    "identity_mismatch",
)

_semantic = None  # lazily created SemanticDrift (only when embeddings are enabled)


def _score_to_tier(score: int) -> Tier:
    """Map a 0-100 risk score to a graduated response tier."""
    if score >= 90:
        return Tier.ISOLATE
    elif score >= 70:
        return Tier.RESTRICT
    elif score >= 40:
        return Tier.STEP_UP
    else:
        return Tier.OBSERVE


def _tier_to_verb(tier: Tier) -> DecisionVerb:
    """Map a response tier to a gateway decision verb."""
    match tier:
        case Tier.ISOLATE:
            return DecisionVerb.DENY
        case Tier.RESTRICT:
            return DecisionVerb.RESTRICT
        case Tier.STEP_UP:
            return DecisionVerb.STEP_UP
        case Tier.OBSERVE:
            return DecisionVerb.ALLOW


def score_event(
    event: ToolCallEvent,
    manifest_overrides: dict[str, object] | None = None,
    *,
    bound_role: str | None = None,
    now: float | None = None,
    tracker: SessionTracker | None = None,
    baselines: BaselineStore | None = None,
    disabled_signals: Collection[str] = (),
    learn: bool | None = None,
) -> Decision:
    """
    Produce a risk decision for a single tool-call event.

    Args:
        event: The tool-call event to score.
        manifest_overrides: Optional manifest changes (e.g. ``{"added_tools": [...]}``) used
            by eval scenarios that simulate an approved manifest update.
        bound_role: The role this agent was provisioned with (registry / first-seen binding).
            The agent is evaluated against *this* role; a different claimed role raises an
            ``identity_mismatch`` signal.
        now: Server clock in seconds (injectable so evaluations can simulate days of traffic).
        tracker: State store; defaults to the live global tracker.  Pass a fresh one to
            replay or evaluate without touching live state.
        baselines: Baseline store; defaults to the process-wide store.
        disabled_signals: Signal names to skip (ablation studies).
        learn: Update the role baseline from this event if it was clean and low-risk.
            Defaults to ``settings.learn_baselines``.
    """
    now = time.time() if now is None else now
    tracker = tracker or get_tracker()
    baselines = baselines or get_baselines()
    off = set(disabled_signals)
    learn = settings.learn_baselines if learn is None else learn

    effective_role = bound_role or event.role
    manifest = get_manifest(effective_role)

    state = tracker.record(event, manifest, now=now)
    agent = tracker.agent(event.agent_id)
    prev_tool = state.tools_used[-2] if len(state.tools_used) >= 2 else START

    reasons: list[Reason] = []

    def add(reason: Reason | None) -> Reason | None:
        if reason is not None and reason.signal not in off:
            reasons.append(reason)
            return reason
        return None

    # Hard-override signals first
    honeypot_reason = add(check_honeypot(event, manifest))

    # Identity: the agent claims a role other than the one it is bound to
    if bound_role and bound_role != event.role:
        add(
            Reason(
                signal="identity_mismatch",
                points=WEIGHT_IDENTITY_MISMATCH,
                text=f"agent is bound to role '{bound_role}' but claims '{event.role}' "
                f"(evaluated as '{bound_role}')",
            )
        )

    # Rule signals
    add(check_role_violation(event, manifest, manifest_overrides, session_state=state))
    add(check_taint_flow(event, manifest, state))
    add(check_sensitivity(event, manifest))
    add(check_velocity(event, manifest, state))
    add(check_misuse_pattern(event, manifest, state))

    # Learned / statistical signals
    baseline = baselines.get(effective_role)
    add(check_sequence_rarity(event, prev_tool, baseline))
    add(check_distribution_drift(list(agent.recent_tools), baseline))

    if settings.enable_embeddings and "semantic_drift" not in off:
        from detector.semantic import SemanticDrift, check_semantic_drift, event_text

        global _semantic
        if _semantic is None:
            _semantic = SemanticDrift()
        window = [event_text(event)]  # lightweight: current event plus recent tools below
        window = [f"{t}" for t in agent.recent_tools] + window
        add(check_semantic_drift(manifest, window, _semantic))

    # Slow-drift accumulator: fed by the anomaly level of this event, excluding itself
    anomaly_points = sum(r.points for r in reasons if r.signal in _ANOMALY_SIGNALS)
    cusum = update_cusum(agent, min(1.0, anomaly_points / 40.0), now)
    add(check_cumulative_drift(cusum))

    # Kill chain (needs server-side session state)
    kc_reason = None if "kill_chain" in off else check_kill_chain_override(state)
    if kc_reason:
        reasons.append(kc_reason)

    # Apply per-signal caps, then total
    for r in reasons:
        cap = SIGNAL_CAPS.get(r.signal)
        if cap is not None and r.points > cap:
            r.points = cap
    total = sum(r.points for r in reasons)

    if honeypot_reason:
        total = max(total, HONEYPOT_OVERRIDE_SCORE)
    if kc_reason:
        total = max(total, KILL_CHAIN_OVERRIDE_SCORE)

    score = min(total, 100)
    tier = _score_to_tier(score)
    verb = _tier_to_verb(tier)

    alert_id: str | None = None
    if tier != Tier.OBSERVE:
        alert_id = f"A-{uuid.uuid4().hex[:8]}"

    reasons.sort(key=lambda r: r.points, reverse=True)

    # Online learning: only clean, in-role, untainted, low-risk events may teach the baseline
    if (
        learn
        and tier == Tier.OBSERVE
        and manifest is not None
        and not _taint_of(event, state)
        and not any(r.signal in _ANOMALY_SIGNALS or r.signal == "role_violation" for r in reasons)
        and event.tool in manifest.allowed_tools
        and bound_role in (None, event.role)
    ):
        baselines.ensure(effective_role).update(prev_tool, event.tool)

    return Decision(
        event_id=event.event_id,
        decision=verb,
        score=score,
        tier=tier,
        reasons=reasons,
        alert_id=alert_id,
    )
