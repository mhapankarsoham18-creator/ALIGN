"""
AIDDS Detector — Signal checkers.

Each function evaluates one risk signal for a ToolCallEvent against
the agent's manifest, returning a Reason (signal name, points, text)
or None if the signal did not fire.

State is kept by the SessionTracker:

* **Session state** - per ``session_id``: counters, taint, byte totals.
* **Agent state**   - per ``agent_id``: a rolling one-hour window, recent taint (with a TTL),
  the recent tool mix and a CUSUM accumulator.  Agent-level state is what stops an attacker
  from resetting their history by simply opening a new session id.

Taint is tracked **on the server**.  Once any event in a session (or any recent event of the
same agent, or of a caller in the delegation chain) carried untrusted content, every later
event is treated as tainted, whether or not the client repeats the taint field.
"""

from __future__ import annotations

import math
import posixpath
import re
import time
from collections import OrderedDict, deque
from collections.abc import Sequence
from dataclasses import dataclass, field

from detector.baseline import (
    DRIFT_MIN_WINDOW,
    DRIFT_THRESHOLD,
    MIN_OBS,
    RARE_P,
    RoleBaseline,
    empirical_distribution,
    js_divergence,
)
from detector.schemas import RoleManifest
from gateway.schemas import Reason, TaintEntry, ToolCallEvent

# ---------------------------------------------------------------------------
# Evasion & Normalization Helpers
# ---------------------------------------------------------------------------

_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://")
_PORT = re.compile(r":\d+$")


def _normalize_resource(res: str | None) -> str:
    """Normalize a resource path against traversal and formatting tricks."""
    if not res:
        return ""
    clean = str(res).strip().replace("\\", "/").lower()
    return posixpath.normpath("/" + clean).lstrip("/")


def _normalize_destination(dest: str | None) -> str:
    """Reduce a destination to its lower-case host (no scheme, user-info, port or path)."""
    if not dest:
        return ""
    d = _SCHEME.sub("", str(dest).strip().lower())
    d = re.split(r"[/?#\\]", d, maxsplit=1)[0]
    if "@" in d:  # user@host: the host is whatever follows the last '@'
        d = d.rsplit("@", 1)[1]
    d = _PORT.sub("", d)
    return d.rstrip(".")


def _is_external(dest: str | None, manifest: RoleManifest | None) -> bool:
    """True when ``dest`` is set and is not on the role's egress allow-list."""
    norm = _normalize_destination(dest)
    if not norm:
        return False
    if manifest is None:
        return True
    return norm not in {_normalize_destination(e) for e in manifest.egress_allowlist}


# ---------------------------------------------------------------------------
# Signal weight constants (caps per signal; see README "Risk score")
# ---------------------------------------------------------------------------

WEIGHT_ROLE_VIOLATION = 40
WEIGHT_TAINT_FLOW = 30
WEIGHT_SENSITIVITY = 15
WEIGHT_SEQUENCE_RARITY = 10
WEIGHT_DISTRIBUTION_DRIFT = 8
WEIGHT_CUMULATIVE_DRIFT = 20
WEIGHT_SEMANTIC_DRIFT = 10
WEIGHT_VELOCITY = 45
WEIGHT_MISUSE = 30
WEIGHT_IDENTITY_MISMATCH = 40

HONEYPOT_OVERRIDE_SCORE = 95
KILL_CHAIN_OVERRIDE_SCORE = 90

# CUSUM parameters (see check_cumulative_drift)
CUSUM_K = 0.15  # per-event allowance: ordinary noise below this never accumulates
CUSUM_H = 1.0  # decision interval
CUSUM_TAU_S = 3 * 24 * 3600.0  # accumulated evidence fades with a 3-day time constant

TAINT_TTL_S = 15 * 60.0  # an agent stays "tainted" for 15 minutes after reading untrusted data
AGENT_WINDOW_S = 3600.0  # rolling window for volume signals
MAX_SESSIONS = 20_000
MAX_AGENTS = 20_000
MAX_LIST = 1_000


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


@dataclass
class SessionState:
    """Accumulated state for one agent session."""

    events_seen: int = 0
    violation_count: int = 0
    out_of_scope_count: int = 0
    total_bytes_out: int = 0
    taint_present: bool = False
    forbidden_access_after_taint: bool = False
    sensitive_access_after_taint: bool = False
    external_egress_after_taint: bool = False
    tools_used: list[str] = field(default_factory=list)
    data_classes_accessed: list[str] = field(default_factory=list)
    bytes_history: list[int] = field(default_factory=list)
    taint_entries: list[TaintEntry] = field(default_factory=list)
    # agent-level rolling-window aggregates (filled by the tracker; 0 when unused)
    agent_window_bytes: int = 0
    agent_window_oos: int = 0
    agent_window_medium: int = 0
    agent_window_large: int = 0


@dataclass
class AgentState:
    """Rolling per-agent state that survives session changes."""

    taint: list[tuple[float, TaintEntry]] = field(default_factory=list)
    window: deque[tuple[float, int, bool]] = field(default_factory=deque)  # (ts, bytes, oos)
    recent_tools: deque[str] = field(default_factory=lambda: deque(maxlen=20))
    cusum: float = 0.0
    cusum_ts: float = 0.0


class SessionTracker:
    """
    Track per-session and per-agent state across events.

    One tracker is shared by the live gateway; the evaluation harness and replay use their
    own instances so they never disturb live state.  Both maps are LRU-bounded.
    """

    def __init__(self, max_sessions: int = MAX_SESSIONS, max_agents: int = MAX_AGENTS) -> None:
        self._sessions: OrderedDict[str, SessionState] = OrderedDict()
        self._agents: OrderedDict[str, AgentState] = OrderedDict()
        self._max_sessions = max_sessions
        self._max_agents = max_agents

    # -- access -----------------------------------------------------------

    def get(self, session_id: str) -> SessionState:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState()
            while len(self._sessions) > self._max_sessions:
                self._sessions.popitem(last=False)
        else:
            self._sessions.move_to_end(session_id)
        return self._sessions[session_id]

    def agent(self, agent_id: str) -> AgentState:
        if agent_id not in self._agents:
            self._agents[agent_id] = AgentState()
            while len(self._agents) > self._max_agents:
                self._agents.popitem(last=False)
        else:
            self._agents.move_to_end(agent_id)
        return self._agents[agent_id]

    def peek_agent(self, agent_id: str) -> AgentState | None:
        return self._agents.get(agent_id)

    def reset_agent(self, agent_id: str) -> None:
        """Forget an agent's rolling state and its sessions (used when an analyst releases it)."""
        self._agents.pop(agent_id, None)
        stale = [s for s in self._sessions if s.startswith(f"{agent_id}::")]
        for s in stale:
            self._sessions.pop(s, None)

    # -- recording --------------------------------------------------------

    @staticmethod
    def _merge_taint(state: SessionState, entries: Sequence[TaintEntry]) -> None:
        known = {t.source for t in state.taint_entries}
        for t in entries:
            if t.source not in known and len(state.taint_entries) < 50:
                state.taint_entries.append(t)
                known.add(t.source)

    def record(
        self, event: ToolCallEvent, manifest: RoleManifest | None, now: float | None = None
    ) -> SessionState:
        """Update session + agent state with a new event and return the session state."""
        now = time.time() if now is None else now
        state = self.get(event.session_id)
        agent = self.agent(event.agent_id)

        state.events_seen += 1
        state.tools_used.append(event.tool)
        state.data_classes_accessed.append(event.data_class.value)
        state.total_bytes_out += event.bytes_out
        state.bytes_history.append(event.bytes_out)
        for lst in (state.tools_used, state.data_classes_accessed, state.bytes_history):
            if len(lst) > MAX_LIST:
                del lst[: MAX_LIST // 2]

        # ---- taint (server-side, sticky) ---------------------------------
        self._merge_taint(state, event.taint)  # client-reported
        agent.taint = [(ts, t) for ts, t in agent.taint if now - ts <= TAINT_TTL_S]
        self._merge_taint(state, [t for _, t in agent.taint])  # this agent's recent taint
        for caller in event.chain:  # delegation: callee inherits its callers' taint
            if caller == event.agent_id:
                continue
            other = self._agents.get(caller)
            if other is not None:
                other.taint = [(ts, t) for ts, t in other.taint if now - ts <= TAINT_TTL_S]
                self._merge_taint(state, [t for _, t in other.taint])
        if event.taint:
            known = {t.source for _, t in agent.taint}
            agent.taint.extend((now, t) for t in event.taint if t.source not in known)
            agent.taint = agent.taint[-50:]
        if state.taint_entries:
            state.taint_present = True

        # ---- taint-dependent flags ---------------------------------------
        dc = event.data_class.value
        if manifest and state.taint_present:
            if dc in manifest.forbidden_data_classes:
                state.forbidden_access_after_taint = True
            if event.sensitivity >= 2:
                state.sensitive_access_after_taint = True
        if state.taint_present and _is_external(event.destination, manifest):
            state.external_egress_after_taint = True

        # ---- scope counters ----------------------------------------------
        out_of_scope = bool(
            manifest
            and (event.tool not in manifest.allowed_tools or dc in manifest.forbidden_data_classes)
        )
        if out_of_scope:
            state.out_of_scope_count += 1
            state.violation_count += 1

        # ---- agent rolling window ----------------------------------------
        agent.window.append((now, event.bytes_out, out_of_scope))
        while agent.window and now - agent.window[0][0] > AGENT_WINDOW_S:
            agent.window.popleft()
        state.agent_window_bytes = sum(b for _, b, _ in agent.window)
        state.agent_window_oos = sum(1 for _, _, o in agent.window if o)
        state.agent_window_medium = sum(1 for _, b, _ in agent.window if b >= 20_000)
        state.agent_window_large = sum(1 for _, b, _ in agent.window if b > 100_000)
        agent.recent_tools.append(event.tool)

        return state


# Global tracker instance
_tracker = SessionTracker()


def get_tracker() -> SessionTracker:
    """Return the global session tracker."""
    return _tracker


def reset_tracker() -> None:
    """Reset the global session tracker (useful for testing)."""
    global _tracker
    _tracker = SessionTracker()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _taint_of(event: ToolCallEvent, state: SessionState | None) -> Sequence[TaintEntry]:
    """Effective taint: what the client reported, else what the server remembers."""
    if event.taint:
        return event.taint
    return state.taint_entries if state is not None else []


# ---------------------------------------------------------------------------
# Individual signal checkers
# ---------------------------------------------------------------------------


def check_role_violation(
    event: ToolCallEvent,
    manifest: RoleManifest | None,
    manifest_overrides: dict[str, object] | None = None,
    session_state: SessionState | None = None,
) -> Reason | None:
    """
    Check whether the tool, data class, or destination violates the manifest.

    Returns up to WEIGHT_ROLE_VIOLATION points.  Checks:
    - unknown role (no manifest): fail closed
    - tool not in allowed_tools
    - data_class in forbidden_data_classes
    - destination not in egress_allowlist (when destination is set)
    - chain delegation violation
    """
    if manifest is None:
        return Reason(
            signal="role_violation",
            points=WEIGHT_ROLE_VIOLATION,
            text=f"unknown role '{event.role}': no manifest to authorise this call (fail closed)",
        )

    points = 0
    texts: list[str] = []

    # -- Handle manifest_change overrides (B02/B06 pattern) --
    effective_tools = list(manifest.allowed_tools)
    if manifest_overrides and "added_tools" in manifest_overrides:
        effective_tools.extend(manifest_overrides["added_tools"])  # type: ignore[arg-type]

    is_allowed_tool = event.tool in effective_tools
    # Allow legitimate delegation calls
    if (
        not is_allowed_tool
        and event.tool == "delegate"
        and manifest.delegation
        and event.resource in manifest.delegation.may_call
    ):
        is_allowed_tool = True

    if not is_allowed_tool:
        points += 20
        texts.append(f"tool '{event.tool}' not in allowed_tools")

    # Data class check (forbidden wins over allowed)
    dc = event.data_class.value
    if dc in manifest.forbidden_data_classes:
        points += 25
        texts.append(f"data_class '{dc}' is forbidden")
    elif dc not in manifest.allowed_data_classes and dc != "unknown":
        points += 10
        texts.append(f"data_class '{dc}' not in allowed_data_classes")

    # Destination check
    if event.destination and _is_external(event.destination, manifest):
        points += 10
        texts.append(f"destination '{event.destination}' not in egress_allowlist")

    # Chain / delegation check — if delegated AND violating, compound penalty
    if (
        event.chain
        and len(event.chain) > 1
        and (not is_allowed_tool or dc in manifest.forbidden_data_classes)
    ):
        points += 20
        texts.append("delegated call violates scope of caller in chain")

    # Session-level escalation: repeated violations compound
    if session_state is None:
        session_state = get_tracker().get(event.session_id)
    repeated = max(session_state.violation_count, session_state.agent_window_oos)
    if repeated >= 2:
        bonus = min(repeated * 3, 10)
        points += bonus
        texts.append(f"repeated violations in window ({repeated} prior)")

    if points == 0:
        return None

    return Reason(
        signal="role_violation",
        points=min(points, WEIGHT_ROLE_VIOLATION),
        text="; ".join(texts),
    )


def check_taint_flow(
    event: ToolCallEvent,
    manifest: RoleManifest | None,
    session_state: SessionState,
) -> Reason | None:
    """
    Check for taint-flow kill chain:
      untrusted read -> sensitive/forbidden access -> external egress.

    Returns up to WEIGHT_TAINT_FLOW points.

    Only fires when taint is present AND the action is forbidden/sensitive.
    A tainted agent doing only in-role work is NOT penalised here.  Taint is the
    server-tracked session/agent/chain taint, not just what this one event reports.
    """
    taint = _taint_of(event, session_state)
    if not taint:
        return None

    points = 0
    texts: list[str] = []
    is_external_egress = bool(event.destination) and _is_external(event.destination, manifest)

    # Taint present + forbidden data access
    if manifest and event.data_class.value in manifest.forbidden_data_classes:
        points += 20
        texts.append(
            f"tainted context accessed forbidden data_class '{event.data_class.value}' "
            f"(taint source: {taint[0].source})"
        )

    # Taint present + high sensitivity access (non-forbidden but still sensitive)
    elif event.sensitivity >= 2 and manifest:
        dc = event.data_class.value
        if dc not in manifest.allowed_data_classes:
            points += 12
            texts.append(
                f"tainted context accessed sensitive resource (sensitivity={event.sensitivity})"
            )

    # Taint present + external egress
    if event.destination and is_external_egress:
        points += 15
        texts.append(f"tainted context sending data externally to '{event.destination}'")

    # Taint present + large data transfer (even to allowed host)
    if event.bytes_out > 50_000:
        points += 15
        texts.append(f"tainted context transferring large payload ({event.bytes_out:,} bytes)")

    # Taint present + tool not in manifest (tainted agent using rogue tools)
    if manifest and event.tool not in manifest.allowed_tools:
        points += 15
        texts.append(f"tainted context using unauthorized tool '{event.tool}'")

    # Full kill chain bonus: forbidden access already happened + now external egress
    if session_state.forbidden_access_after_taint and event.destination and is_external_egress:
        points += 5
        texts.append("complete kill chain: taint -> forbidden access -> external egress")

    if points == 0:
        return None

    return Reason(
        signal="taint_flow",
        points=min(points, WEIGHT_TAINT_FLOW),
        text="; ".join(texts),
    )


def check_sensitivity(
    event: ToolCallEvent,
    manifest: RoleManifest | None,
) -> Reason | None:
    """
    Score based on the sensitivity of the data being accessed.

    Returns up to WEIGHT_SENSITIVITY points.  Only fires when accessing sensitive data
    outside normal in-role scope.  In-role access to sensitive data is expected.
    """
    if manifest and event.data_class.value in manifest.allowed_data_classes:
        return None

    if event.sensitivity == 0:
        return None

    points_map = {1: 3, 2: 10, 3: 15}
    points = points_map.get(event.sensitivity, 0)
    if points == 0:
        return None

    return Reason(
        signal="sensitivity",
        points=min(points, WEIGHT_SENSITIVITY),
        text=f"accessing sensitivity={event.sensitivity} data "
        f"(data_class='{event.data_class.value}') outside allowed scope",
    )


def check_misuse_pattern(
    event: ToolCallEvent,
    manifest: RoleManifest | None,
    session_state: SessionState,
) -> Reason | None:
    """
    Detect misuse patterns where an agent uses tools to access forbidden or
    out-of-scope data (mimicry attack, agent chain compromise).

    Returns up to WEIGHT_MISUSE points.
    """
    if manifest is None:
        return None

    points = 0
    texts: list[str] = []
    taint = _taint_of(event, session_state)
    dc = event.data_class.value

    # Allowed tool but forbidden data class = high-confidence misuse (mimicry)
    if event.tool in manifest.allowed_tools and dc in manifest.forbidden_data_classes:
        points += 30
        texts.append(
            f"allowed tool '{event.tool}' used to access forbidden data_class '{dc}' "
            f"(mimicry pattern)"
        )

    # Delegated agent chain exceeds caller authority
    elif event.chain and len(event.chain) >= 2:
        if (
            dc in manifest.forbidden_data_classes
            or event.tool not in manifest.allowed_tools
            or (manifest.delegation and event.tool not in manifest.delegation.pass_scopes)
        ):
            points += 30
            texts.append(
                f"delegated agent chain ({' -> '.join(event.chain)}) exceeds caller authority "
                f"(tool '{event.tool}', data_class '{dc}' outside delegation scope)"
            )

    # Allowed tool but data class not in allowed list + high sensitivity
    elif (
        event.tool in manifest.allowed_tools
        and dc not in manifest.allowed_data_classes
        and dc != "unknown"
        and event.sensitivity >= 2
    ):
        points += 15
        texts.append(
            f"allowed tool '{event.tool}' accessing out-of-scope sensitive data "
            f"(data_class='{dc}', sensitivity={event.sensitivity})"
        )

    # Tainted context using unauthorized tool for data egress
    elif taint and event.tool not in manifest.allowed_tools and event.bytes_out > 50_000:
        points += 20
        texts.append(
            f"tainted context using unauthorized tool '{event.tool}' to egress data "
            f"({event.bytes_out:,} bytes)"
        )

    if points == 0:
        return None

    return Reason(signal="misuse_pattern", points=min(points, WEIGHT_MISUSE), text="; ".join(texts))


def check_velocity(
    event: ToolCallEvent,
    manifest: RoleManifest | None,
    session_state: SessionState,
) -> Reason | None:
    """
    Check for velocity anomalies: excessive out-of-scope calls, unusually large byte
    volumes, or cumulative exfiltration.  Volume is measured per **agent over a rolling
    hour** (and per session, whichever is larger), so opening a fresh session id does not
    reset the budget.

    Returns up to WEIGHT_VELOCITY points.
    """
    points = 0
    texts: list[str] = []

    oos = max(session_state.out_of_scope_count, session_state.agent_window_oos)
    total_bytes = max(session_state.total_bytes_out, session_state.agent_window_bytes)
    large_events = max(
        sum(1 for b in session_state.bytes_history if b > 100_000), session_state.agent_window_large
    )
    medium_events = max(
        sum(1 for b in session_state.bytes_history if b >= 20_000),
        session_state.agent_window_medium,
    )

    # Multiple out-of-scope calls
    if oos >= 3:
        bonus = min(oos * 2, 8)
        points += bonus
        texts.append(f"{oos} out-of-scope calls in window")

    # Excessive bytes_out (check against manifest limits)
    if manifest and total_bytes > manifest.limits.max_bytes_out_per_hour:
        points += 25
        texts.append(
            f"total bytes_out ({total_bytes:,}) exceeds "
            f"hourly limit ({manifest.limits.max_bytes_out_per_hour:,})"
        )
    elif manifest and total_bytes > manifest.limits.max_bytes_out_per_hour * 0.20:
        ratio = total_bytes / manifest.limits.max_bytes_out_per_hour
        approach_points = min(int(ratio * 30), 20)
        points += approach_points
        texts.append(
            f"total bytes_out ({total_bytes:,}) at "
            f"{ratio:.0%} of hourly limit ({manifest.limits.max_bytes_out_per_hour:,})"
        )

    # Large single-event payload
    if event.bytes_out > 1_000_000:
        points += 15
        texts.append(f"very large single payload ({event.bytes_out:,} bytes)")
    elif event.bytes_out > 100_000:
        points += 10
        texts.append(f"large single payload ({event.bytes_out:,} bytes)")

    # Repeated large payloads — pattern of exfiltration
    if large_events >= 2:
        bonus = min(large_events * 5, 15)
        points += bonus
        texts.append(f"{large_events} events with >100KB payloads in window")

    # Micro-batched exfiltration detection: multiple medium-sized outbound payloads
    if medium_events >= 4 and total_bytes >= 100_000:
        bonus = min(medium_events * 3, 15)
        points += bonus
        texts.append(
            f"micro-batched exfiltration pattern ({medium_events} chunks, "
            f"{total_bytes:,} bytes total)"
        )

    if points == 0:
        return None

    return Reason(signal="velocity", points=min(points, WEIGHT_VELOCITY), text="; ".join(texts))


def _get_bytes_history(state: SessionState) -> list[int]:
    """Return per-event bytes_out history from session state."""
    return getattr(state, "bytes_history", [])


def check_honeypot(
    event: ToolCallEvent,
    manifest: RoleManifest | None,
) -> Reason | None:
    r"""
    Check whether the event touches a honeypot resource.

    If the resource matches any honeypot across any manifest, this returns
    HONEYPOT_OVERRIDE_SCORE — a hard override.  Resistant to path traversal (../),
    path casing, and separators (\ vs /).
    """
    from detector.manifest_loader import get_manifests

    norm_res = _normalize_resource(event.resource)
    if not norm_res:
        return None

    if manifest:
        norm_honeypots = {_normalize_resource(h): h for h in manifest.honeypots}
        if norm_res in norm_honeypots:
            orig = norm_honeypots[norm_res]
            return Reason(
                signal="honeypot",
                points=HONEYPOT_OVERRIDE_SCORE,
                text=f"honeypot resource '{orig}' accessed - immediate isolation",
            )

    # Also check other manifests' honeypots (cross-role snooping)
    for role, m in get_manifests().items():
        norm_role_honeypots = {_normalize_resource(h): h for h in m.honeypots}
        if norm_res in norm_role_honeypots:
            orig = norm_role_honeypots[norm_res]
            return Reason(
                signal="honeypot",
                points=HONEYPOT_OVERRIDE_SCORE,
                text=f"honeypot resource '{orig}' (from role '{role}') accessed "
                f"- immediate isolation",
            )

    return None


def check_kill_chain_override(
    session_state: SessionState,
) -> Reason | None:
    """
    Hard override: if the session shows the complete kill chain
    (taint -> forbidden access -> external egress), ensure score >= 90.
    """
    if (
        session_state.taint_present
        and session_state.forbidden_access_after_taint
        and session_state.external_egress_after_taint
    ):
        return Reason(
            signal="kill_chain",
            points=KILL_CHAIN_OVERRIDE_SCORE,
            text="complete kill chain detected: "
            "untrusted input -> forbidden data access -> external egress",
        )
    return None


# ---------------------------------------------------------------------------
# Learned / statistical signals
# ---------------------------------------------------------------------------


def check_sequence_rarity(
    event: ToolCallEvent, prev_tool: str, baseline: RoleBaseline | None
) -> Reason | None:
    """A tool transition that is very unlikely under the role's learned Markov model."""
    if baseline is None or baseline.n_obs < MIN_OBS:
        return None  # cold start: rely on the manifest rules
    p = baseline.prob(prev_tool, event.tool)
    if p >= RARE_P:
        return None
    points = max(1, round(WEIGHT_SEQUENCE_RARITY * (1 - p / RARE_P)))
    return Reason(
        signal="sequence_rarity",
        points=min(points, WEIGHT_SEQUENCE_RARITY),
        text=f"transition '{prev_tool}' -> '{event.tool}' has probability {p:.4f} "
        f"under the '{baseline.role}' behaviour model",
    )


def check_distribution_drift(
    recent_tools: Sequence[str], baseline: RoleBaseline | None
) -> Reason | None:
    """The agent's recent tool mix has drifted from the role's learned mix (JS divergence)."""
    if baseline is None or baseline.n_obs < MIN_OBS or len(recent_tools) < DRIFT_MIN_WINDOW:
        return None
    jsd = js_divergence(empirical_distribution(recent_tools), baseline.tool_distribution())
    if jsd <= DRIFT_THRESHOLD:
        return None
    frac = min(1.0, (jsd - DRIFT_THRESHOLD) / DRIFT_THRESHOLD)
    points = max(1, round(WEIGHT_DISTRIBUTION_DRIFT * frac))
    return Reason(
        signal="distribution_drift",
        points=min(points, WEIGHT_DISTRIBUTION_DRIFT),
        text=f"recent tool mix diverges from the role baseline (JS divergence {jsd:.2f})",
    )


def update_cusum(agent: AgentState, anomaly: float, now: float) -> float:
    """
    One-sided CUSUM with exponential fading.

        S_t = max(0, S_{t-1} * exp(-dt / tau) + a_t - k)

    ``a_t`` in [0, 1] is the event's anomaly level from the rule/statistical signals.  Normal
    events (a_t = 0) drain the accumulator; repeated small anomalies that never trip a
    per-event threshold build it up, even across sessions and days.
    """
    if agent.cusum_ts:
        dt = max(0.0, now - agent.cusum_ts)
        agent.cusum *= math.exp(-dt / CUSUM_TAU_S)
    agent.cusum_ts = now
    agent.cusum = max(0.0, agent.cusum + anomaly - CUSUM_K)
    return agent.cusum


def check_cumulative_drift(cusum: float) -> Reason | None:
    """Slow-drift signal: the CUSUM accumulator crossed half the decision interval."""
    if cusum < 0.5 * CUSUM_H:
        return None
    points = min(
        WEIGHT_CUMULATIVE_DRIFT, max(1, round(WEIGHT_CUMULATIVE_DRIFT * cusum / (2 * CUSUM_H)))
    )
    return Reason(
        signal="cumulative_drift",
        points=points,
        text=f"accumulated small deviations (CUSUM {cusum:.2f}, alarm at {CUSUM_H:.1f})",
    )
