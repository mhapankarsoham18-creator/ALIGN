"""
AIDDS Gateway — FastAPI application.

Every /v1/tool-calls request is scored by the detector, **enforced** (isolated agents are
denied, restricted agents become read-only), stored in the event store and returned to the
caller as a decision.  Everything else under /v1 is the analyst / dashboard API.

Security model
--------------
* ``AIDDS_GATEWAY_API_KEY``  -> required (header ``X-Gateway-Key``) on POST /v1/tool-calls.
* ``AIDDS_ANALYST_API_KEY``  -> required (header ``X-API-Key``) on all other /v1 endpoints.
* Both unset = open development mode (a warning is logged and shown in /healthz).
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import pathlib
import re
import time
from collections import deque
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Annotated, Literal, cast

import yaml
from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from detector.baseline import get_baselines
from detector.engine import score_event
from detector.manifest_loader import (
    get_manifest,
    get_manifests,
    rejected_manifests,
    reload_manifests,
)
from detector.registry import registered_role
from detector.schemas import RoleManifest
from detector.signals import SessionTracker, get_tracker, reset_tracker
from detector.signing import load_trusted_keys, verify_manifest
from gateway.config import settings
from gateway.database import close_db, get_session, init_db
from gateway.schemas import Action, Decision, DecisionVerb, Reason, Tier, ToolCallEvent
from gateway.store import AgentStateRecord, EventRepository

logger = logging.getLogger("aidds.gateway")

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def _key_ok(provided: str | None, expected: str | None) -> bool:
    if not expected:  # not configured -> open development mode
        return True
    return provided is not None and hmac.compare_digest(provided.encode(), expected.encode())


async def require_gateway(x_gateway_key: Annotated[str | None, Header()] = None) -> None:
    if not _key_ok(x_gateway_key, settings.gateway_api_key):
        raise HTTPException(status_code=401, detail="invalid or missing X-Gateway-Key")


async def require_analyst(x_api_key: Annotated[str | None, Header()] = None) -> None:
    if not _key_ok(x_api_key, settings.analyst_api_key):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


async def require_analyst_stream(
    x_api_key: Annotated[str | None, Header()] = None,
    key: Annotated[str | None, Query()] = None,
) -> None:
    """EventSource cannot set headers, so the stream also accepts ``?key=``."""
    if not (
        _key_ok(x_api_key, settings.analyst_api_key) and settings.analyst_api_key is None
    ) and not _key_ok(key or x_api_key, settings.analyst_api_key):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


ANALYST = [Depends(require_analyst)]

# ---------------------------------------------------------------------------
# Real-time fan-out and latency metrics
# ---------------------------------------------------------------------------

_subscribers: list[asyncio.Queue[str]] = []
MAX_SUBSCRIBERS = 200
_latencies: deque[tuple[float, float]] = deque(maxlen=2000)  # (score_ms, total_ms)


def _broadcast_event(payload: dict[str, object]) -> None:
    """Broadcast an event payload to all active SSE subscribers."""
    msg = json.dumps(payload, default=str)
    for q in list(_subscribers):
        with suppress(Exception):
            q.put_nowait(msg)


def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 3)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Create tables, validate manifests and baselines on startup; persist on shutdown."""
    await init_db()
    loaded = get_manifests()
    rejected = rejected_manifests()
    logger.info("manifests loaded: %s", sorted(loaded))
    if rejected:
        logger.error("manifests REJECTED (roles will fail closed): %s", rejected)
    if not settings.analyst_api_key:
        logger.warning(
            "AIDDS_ANALYST_API_KEY is not set: analyst endpoints are OPEN (development mode only)"
        )
    if settings.demo_mode:
        logger.warning("demo mode is ON: /v1/demo/* endpoints are enabled")
    get_baselines()
    yield
    if settings.persist_baselines:
        get_baselines().save_dir(settings.baselines_dir)
    await close_db()


app = FastAPI(
    title=settings.app_name,
    description="Identity Drift Detection for Autonomous AI Agents",
    version="0.2.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.2.0"
    auth: str = "disabled (development)"
    manifests_loaded: int = 0
    manifests_rejected: int = 0
    baselines_loaded: int = 0
    demo_mode: bool = False


@app.get("/healthz", response_model=HealthResponse, tags=["ops"])
@app.get("/health", response_model=HealthResponse, tags=["ops"])
async def healthz() -> HealthResponse:
    """Liveness and readiness probe (no secrets, no auth)."""
    rejected = rejected_manifests()
    return HealthResponse(
        status="degraded" if rejected else "ok",
        auth="enabled" if settings.analyst_api_key else "disabled (development)",
        manifests_loaded=len(get_manifests()),
        manifests_rejected=len(rejected),
        baselines_loaded=len(get_baselines().roles()),
        demo_mode=settings.demo_mode,
    )


# ---------------------------------------------------------------------------
# Core: tool-call interception + enforcement
# ---------------------------------------------------------------------------


def _contained(
    event: ToolCallEvent, tier: Tier, verb: DecisionVerb, text: str, signal: str
) -> Decision:
    return Decision(
        event_id=event.event_id,
        decision=verb,
        score=100 if tier == Tier.ISOLATE else 70,
        tier=tier,
        reasons=[Reason(signal=signal, points=100 if tier == Tier.ISOLATE else 70, text=text)],
        alert_id=None,
    )


def _enforce_state(state: AgentStateRecord | None, event: ToolCallEvent) -> Decision | None:
    """Return a blocking decision if the agent's containment state forbids this call."""
    if state is None:
        return None
    if state.status == "isolated":
        return _contained(
            event,
            Tier.ISOLATE,
            DecisionVerb.DENY,
            f"agent '{event.agent_id}' is isolated pending analyst review: all calls denied",
            "agent_isolated",
        )
    return None


def _enforce_restriction(
    state: AgentStateRecord | None, event: ToolCallEvent, decision: Decision
) -> Decision:
    """A restricted agent is read-only with no outbound egress."""
    if state is None or state.status != "restricted":
        return decision
    if event.action != Action.READ or event.destination:
        reasons = [
            Reason(
                signal="containment",
                points=0,
                text="agent is restricted (read-only, no egress): this call was blocked",
            ),
            *decision.reasons,
        ]
        return decision.model_copy(update={"decision": DecisionVerb.DENY, "reasons": reasons})
    return decision


async def _process_event(event: ToolCallEvent) -> Decision:
    """Score, enforce, persist and broadcast one tool call."""
    start = time.perf_counter_ns()

    # 1. Identity + containment state (DB failure must not stop detection)
    state: AgentStateRecord | None = None
    stored_role: str | None = None
    try:
        async with get_session() as session:
            repo = EventRepository(session)
            state = await repo.get_agent_state(event.agent_id)
            stored_role = state.role if state is not None else None
    except Exception:
        logger.exception("could not read agent state; continuing with detection only")
    bound_role = registered_role(event.agent_id) or stored_role

    # 2. Decide
    blocked = _enforce_state(state, event)
    score_start = time.perf_counter_ns()
    if blocked is not None:
        decision = blocked
    else:
        decision = score_event(event, bound_role=bound_role)
        decision = _enforce_restriction(state, event, decision)
    score_ms = (time.perf_counter_ns() - score_start) / 1_000_000

    # 3. Human step-up approvals + persistence
    try:
        async with get_session() as session:
            repo = EventRepository(session)
            if blocked is None and decision.tier == Tier.STEP_UP:
                approved = await repo.find_approval(
                    event.agent_id, event.tool, event.resource, "approved"
                )
                if approved is not None:
                    await repo.consume_approval(approved)
                    decision = decision.model_copy(
                        update={
                            "decision": DecisionVerb.ALLOW,
                            "reasons": [
                                Reason(
                                    signal="human_approval",
                                    points=0,
                                    text=f"released by analyst approval {approved.approval_id}",
                                ),
                                *decision.reasons,
                            ],
                        }
                    )
                elif decision.alert_id:
                    await repo.create_pending_approval(
                        decision.alert_id, event.agent_id, event.tool, event.resource
                    )
            await repo.create(
                event_dict=event.model_dump(mode="python"),
                decision_dict=decision.model_dump(mode="python"),
            )
    except Exception:
        logger.exception("could not persist event %s (decision still enforced)", event.event_id)

    total_ms = (time.perf_counter_ns() - start) / 1_000_000
    _latencies.append((score_ms, total_ms))

    _broadcast_event(
        {
            "type": "event",
            "event": event.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
            "elapsed_ms": total_ms,
        }
    )
    if settings.debug:
        logger.info(
            "event=%s score=%s tier=%s total=%.2fms",
            event.event_id,
            decision.score,
            decision.tier.value,
            total_ms,
        )
    return decision


@app.post(
    "/v1/tool-calls",
    response_model=Decision,
    status_code=status.HTTP_200_OK,
    tags=["gateway"],
    dependencies=[Depends(require_gateway)],
)
async def handle_tool_call(event: ToolCallEvent) -> Decision:
    """
    Receive a tool-call event, score it, enforce containment, store it, return a decision.

    The caller (the agent runtime / proxy) must honour the decision: ``allow`` proceeds,
    ``step_up`` waits for a human, ``restrict`` and ``deny`` block the call.
    """
    return await _process_event(event)


# ---------------------------------------------------------------------------
# Live stream (declared BEFORE /v1/events/{event_id} so "stream" is not read as an id)
# ---------------------------------------------------------------------------


@app.get(
    "/v1/events/stream",
    tags=["events"],
    dependencies=[Depends(require_analyst_stream)],
)
async def events_stream() -> StreamingResponse:
    """Stream real-time tool-call events and decisions (Server-Sent Events)."""
    if len(_subscribers) >= MAX_SUBSCRIBERS:
        raise HTTPException(status_code=503, detail="too many stream subscribers")

    async def sse_gen() -> AsyncGenerator[str, None]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=200)
        _subscribers.append(q)
        try:
            yield 'event: ping\ndata: {"status": "connected"}\n\n'
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"event: update\ndata: {msg}\n\n"
                except TimeoutError:
                    yield ": keepalive\n\n"  # keeps proxies from closing an idle stream
        except asyncio.CancelledError:
            pass
        finally:
            if q in _subscribers:
                _subscribers.remove(q)

    return StreamingResponse(
        sse_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Event query and replay
# ---------------------------------------------------------------------------


class EventListItem(BaseModel):
    """Lightweight event summary for list responses."""

    event_id: str
    ts: str
    agent_id: str
    role: str
    session_id: str
    tool: str
    action: str
    resource: str
    data_class: str
    sensitivity: int
    destination: str | None
    bytes_out: int
    decision: str | None
    score: int | None
    tier: str | None


class EventDetail(EventListItem):
    """Full event with payload and alert info."""

    payload: dict[str, object]
    alert_id: str | None


class EventListResponse(BaseModel):
    """Paginated event list."""

    total: int
    events: list[EventListItem]


class ReplayResult(BaseModel):
    """Result of replaying events through the detector."""

    replayed: int
    results: list[dict[str, object]]


@app.get("/v1/events", response_model=EventListResponse, tags=["events"], dependencies=ANALYST)
async def list_events(
    agent_id: str | None = Query(None),
    role: str | None = Query(None),
    session_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> EventListResponse:
    """List stored events with optional filters, newest first."""
    async with get_session() as session:
        repo = EventRepository(session)
        records = await repo.list_events(
            agent_id=agent_id,
            role=role,
            session_id=session_id,
            limit=limit,
            offset=offset,
        )
        total = await repo.count()

    events = [
        EventListItem(
            event_id=r.event_id,
            ts=r.ts.isoformat(),
            agent_id=r.agent_id,
            role=r.role,
            session_id=r.session_id,
            tool=r.tool,
            action=r.action,
            resource=r.resource,
            data_class=r.data_class,
            sensitivity=r.sensitivity,
            destination=r.destination,
            bytes_out=r.bytes_out,
            decision=r.decision,
            score=r.score,
            tier=r.tier,
        )
        for r in records
    ]
    return EventListResponse(total=total, events=events)


@app.get("/v1/events/{event_id}", response_model=EventDetail, tags=["events"], dependencies=ANALYST)
async def get_event(event_id: str) -> EventDetail:
    """Get full event detail including payload."""
    async with get_session() as session:
        repo = EventRepository(session)
        record = await repo.get(event_id)

    if record is None:
        raise HTTPException(status_code=404, detail="Event not found")

    return EventDetail(
        event_id=record.event_id,
        ts=record.ts.isoformat(),
        agent_id=record.agent_id,
        role=record.role,
        session_id=record.session_id,
        tool=record.tool,
        action=record.action,
        resource=record.resource,
        data_class=record.data_class,
        sensitivity=record.sensitivity,
        destination=record.destination,
        bytes_out=record.bytes_out,
        decision=record.decision,
        score=record.score,
        tier=record.tier,
        payload=json.loads(record.payload),
        alert_id=record.alert_id,
    )


@app.post("/v1/events/replay", response_model=ReplayResult, tags=["events"], dependencies=ANALYST)
async def replay_events(
    session_id: str | None = Query(None),
    agent_id: str | None = Query(None),
) -> ReplayResult:
    """
    Replay stored events through the current detector and rules.

    Uses a throw-away tracker and never updates baselines, so replaying cannot change the
    live state of any agent or session.
    """
    async with get_session() as session:
        repo = EventRepository(session)
        records = await repo.list_for_replay(session_id=session_id, agent_id=agent_id)

    tracker = SessionTracker()
    results: list[dict[str, object]] = []
    for record in records:
        event = ToolCallEvent.model_validate(json.loads(record.payload))
        new_decision = score_event(
            event,
            bound_role=registered_role(event.agent_id),
            tracker=tracker,
            now=event.ts.timestamp(),
            learn=False,
        )
        results.append(
            {
                "event_id": record.event_id,
                "original_score": record.score,
                "original_tier": record.tier,
                "replay_score": new_decision.score,
                "replay_tier": new_decision.tier.value,
                "changed": record.score != new_decision.score,
            }
        )

    return ReplayResult(replayed=len(results), results=results)


# ---------------------------------------------------------------------------
# Agents & Risk
# ---------------------------------------------------------------------------

_RESTRICTIONS = {
    "isolated": ["quarantine", "all_calls_denied", "credential_revocation_requested"],
    "restricted": ["read_only", "no_egress", "sensitive_scopes_revoked"],
    "step_up": ["human_approval_required"],
}


def _demo_agent(agent_id: str, role: str) -> dict[str, object]:
    return {
        "agent_id": agent_id,
        "role": role,
        "status": "healthy",
        "score": 0,
        "tier": "observe",
        "event_count": 0,
        "is_tainted": False,
        "last_event_ts": None,
        "restrictions": [],
    }


@app.get("/v1/agents", tags=["agents"], dependencies=ANALYST)
async def list_agents() -> list[dict[str, object]]:
    """List all tracked agents with their live risk posture."""
    async with get_session() as session:
        repo = EventRepository(session)
        states = await repo.list_agent_states()

    result: list[dict[str, object]] = []
    found_ids = set()
    for s in states:
        found_ids.add(s.agent_id)
        result.append(
            {
                "agent_id": s.agent_id,
                "role": s.role,
                "status": s.status,
                "score": s.score,
                "tier": s.tier,
                "event_count": s.event_count,
                "is_tainted": s.is_tainted,
                "last_event_ts": s.last_event_ts.isoformat() if s.last_event_ts else None,
                "restrictions": _RESTRICTIONS.get(s.status, []),
            }
        )

    if settings.demo_mode:  # pre-list the two demo agents so the dashboard is not empty
        if "procurement-bot-04" not in found_ids:
            result.insert(0, _demo_agent("procurement-bot-04", "procurement-agent"))
        if "support-bot-02" not in found_ids:
            result.append(_demo_agent("support-bot-02", "support-agent"))

    return result


@app.get("/v1/agents/{agent_id}/risk", tags=["agents"], dependencies=ANALYST)
async def get_agent_risk(agent_id: str) -> dict[str, object]:
    """Current score, tier, active restrictions for an agent."""
    async with get_session() as session:
        repo = EventRepository(session)
        state = await repo.get_agent_state(agent_id)

    if state:
        return {
            "agent_id": agent_id,
            "role": state.role,
            "score": state.score,
            "tier": state.tier,
            "status": state.status,
            "is_tainted": state.is_tainted,
            "restrictions": _RESTRICTIONS.get(state.status, []),
        }

    return {
        "agent_id": agent_id,
        "score": 0,
        "tier": "observe",
        "status": "healthy",
        "restrictions": [],
    }


@app.post("/v1/agents/{agent_id}/release", tags=["agents"], dependencies=ANALYST)
async def release_agent(agent_id: str) -> dict[str, str]:
    """Lift isolation after review. Also forgets the agent's rolling detector state."""
    async with get_session() as session:
        repo = EventRepository(session)
        state = await repo.release_agent(agent_id)
        if state is None:
            raise HTTPException(status_code=404, detail="Unknown agent")
        await repo.add_audit("analyst", "agent.release", agent_id)

    get_tracker().reset_agent(agent_id)
    _broadcast_event({"type": "agent_released", "agent_id": agent_id})
    return {"agent_id": agent_id, "status": "released"}


# ---------------------------------------------------------------------------
# Alerts & Feedback
# ---------------------------------------------------------------------------


def _alert_dict(r: object) -> dict[str, object]:
    from gateway.store import AlertRecord

    assert isinstance(r, AlertRecord)
    try:
        reasons = json.loads(r.reasons_json)
    except Exception:
        reasons = []
    return {
        "alert_id": r.alert_id,
        "event_id": r.event_id,
        "agent_id": r.agent_id,
        "role": r.role,
        "session_id": r.session_id,
        "ts": r.ts.isoformat(),
        "score": r.score,
        "tier": r.tier,
        "decision": r.decision,
        "tool": r.tool,
        "resource": r.resource,
        "reasons": reasons,
        "feedback": r.feedback,
        "status": r.status,
    }


@app.get("/v1/alerts", tags=["alerts"], dependencies=ANALYST)
async def list_alerts(
    alert_status: str | None = Query(None, alias="status"),
    tier: str | None = Query(None),
) -> list[dict[str, object]]:
    """List alerts, newest first."""
    async with get_session() as session:
        repo = EventRepository(session)
        records = await repo.list_alerts(alert_status=alert_status, tier=tier)
    return [_alert_dict(r) for r in records]


@app.get("/v1/alerts/{alert_id}", tags=["alerts"], dependencies=ANALYST)
async def get_alert(alert_id: str) -> dict[str, object]:
    """Full alert detail."""
    async with get_session() as session:
        repo = EventRepository(session)
        r = await repo.get_alert(alert_id)
    if r is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_dict(r)


class FeedbackRequest(BaseModel):
    feedback: Literal["confirmed", "false_alarm"] = "confirmed"


@app.post("/v1/alerts/{alert_id}/feedback", tags=["alerts"], dependencies=ANALYST)
async def alert_feedback(
    alert_id: str,
    body: FeedbackRequest | None = None,
) -> dict[str, str]:
    """Analyst marks false_alarm or confirmed."""
    fb = body.feedback if body else "confirmed"
    async with get_session() as session:
        repo = EventRepository(session)
        alert = await repo.update_alert_feedback(alert_id, fb)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        await repo.add_audit("analyst", "alert.feedback", alert_id, fb)

    _broadcast_event({"type": "alert_feedback", "alert_id": alert_id, "feedback": fb})
    return {"alert_id": alert_id, "status": "accepted", "feedback": fb}


# ---------------------------------------------------------------------------
# Approvals (human step-up)
# ---------------------------------------------------------------------------


class ApprovalRequest(BaseModel):
    status: Literal["approved", "denied"] = "approved"


@app.get("/v1/approvals", tags=["approvals"], dependencies=ANALYST)
async def list_approvals(
    status_filter: str | None = Query(None, alias="status"),
) -> list[dict[str, object]]:
    """Pending and decided step-up approvals, newest first."""
    async with get_session() as session:
        repo = EventRepository(session)
        records = await repo.list_approvals(status_filter)
    return [
        {
            "approval_id": a.approval_id,
            "agent_id": a.agent_id,
            "tool": a.action_type,
            "resource": a.resource,
            "status": a.status,
            "created_at": a.created_at.isoformat(),
        }
        for a in records
    ]


@app.post("/v1/approvals/{approval_id}", tags=["approvals"], dependencies=ANALYST)
async def handle_approval(
    approval_id: str,
    body: ApprovalRequest | None = None,
) -> dict[str, str]:
    """Human approves or denies a paused action. An approval releases the same call once."""
    st = body.status if body else "approved"
    async with get_session() as session:
        repo = EventRepository(session)
        rec = await repo.decide_approval(approval_id, st)
        if rec is None:
            raise HTTPException(status_code=404, detail="Approval not found")
        if rec.status != st:
            raise HTTPException(status_code=409, detail=f"Approval already {rec.status}")
        await repo.add_audit("analyst", f"approval.{st}", approval_id)

    _broadcast_event({"type": "approval", "approval_id": approval_id, "status": st})
    return {"approval_id": approval_id, "status": "accepted", "decision": st}


# ---------------------------------------------------------------------------
# Manifests (signed)
# ---------------------------------------------------------------------------

_ROLE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


@app.get("/v1/manifests", tags=["manifests"], dependencies=ANALYST)
async def list_manifests() -> dict[str, object]:
    """Loaded manifests (signature-verified) and any that were rejected."""
    return {
        "loaded": [
            {"role": m.role, "version": m.version, "owner": m.owner}
            for m in get_manifests().values()
        ],
        "rejected": rejected_manifests(),
    }


@app.put("/v1/manifests/{role}", tags=["manifests"], dependencies=ANALYST)
async def upload_manifest(role: str, manifest: RoleManifest) -> dict[str, object]:
    """
    Install a new manifest version.  The manifest must be signed by a trusted key, its role must
    match the URL and its version must be higher than the one in force.
    """
    if not _ROLE_RE.match(role) or manifest.role != role:
        raise HTTPException(status_code=400, detail="role in URL and body must match a valid name")
    if settings.require_signed_manifests:
        ok, reason = verify_manifest(manifest, load_trusted_keys(settings.trusted_keys_file))
        if not ok:
            raise HTTPException(status_code=403, detail=f"manifest signature rejected: {reason}")
    current = get_manifest(role)
    if current is not None and manifest.version <= current.version:
        raise HTTPException(
            status_code=409,
            detail=f"version {manifest.version} must be greater than current {current.version}",
        )

    target = pathlib.Path(settings.manifests_dir) / f"{role}.yaml"
    tmp = target.with_suffix(".yaml.tmp")
    tmp.write_text(
        yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
    )
    tmp.replace(target)
    reload_manifests()

    async with get_session() as session:
        repo = EventRepository(session)
        await repo.add_audit("analyst", "manifest.install", role, f"version {manifest.version}")
    return {"role": role, "version": manifest.version, "status": "accepted"}


# ---------------------------------------------------------------------------
# Audit + metrics
# ---------------------------------------------------------------------------


@app.get("/v1/audit", tags=["audit"], dependencies=ANALYST)
async def list_audit(limit: int = Query(100, ge=1, le=1000)) -> list[dict[str, object]]:
    """Append-only trail of privileged actions."""
    async with get_session() as session:
        repo = EventRepository(session)
        rows = await repo.list_audit(limit)
    return [
        {
            "ts": r.ts.isoformat(),
            "actor": r.actor,
            "action": r.action,
            "target": r.target,
            "detail": r.detail,
        }
        for r in rows
    ]


@app.get("/v1/metrics/latency", tags=["ops"], dependencies=ANALYST)
async def latency_metrics() -> dict[str, object]:
    """Measured decision latency over the last 2000 calls (this process)."""
    score = [s for s, _ in _latencies]
    total = [t for _, t in _latencies]
    return {
        "count": len(total),
        "score_p50_ms": _pct(score, 0.50),
        "score_p95_ms": _pct(score, 0.95),
        "total_p50_ms": _pct(total, 0.50),
        "total_p95_ms": _pct(total, 0.95),
        "total_p99_ms": _pct(total, 0.99),
    }


@app.get("/v1/eval/metrics", tags=["eval"], dependencies=ANALYST)
async def get_eval_metrics() -> dict[str, object]:
    """Quality-gate results from eval/report.json (never invented: absent until generated)."""
    report_path = Path(__file__).resolve().parent.parent / "eval" / "report.json"
    if not report_path.exists():
        return {"status": "not_generated", "hint": "run: python -m eval.run"}
    try:
        data = cast(dict[str, object], json.loads(report_path.read_text(encoding="utf-8")))
    except Exception as e:
        return {"status": "error", "error": str(e)}

    per = cast(list[dict[str, object]], data.get("per_scenario", []))
    data["scenarios"] = [
        {
            "scenario_id": s.get("id"),
            "scenario_name": s.get("name"),
            "label": s.get("label"),
            "expected_tier": s.get("expected_tier"),
            "max_score": s.get("max_score"),
            "max_tier": s.get("max_tier"),
            "time_to_detect_events": s.get("time_to_detect_events", s.get("detection_index")),
            "passed": s.get("detected"),
        }
        for s in per
    ]
    held = report_path.parent / "heldout_report.json"
    if held.exists():
        with suppress(Exception):
            data["heldout"] = json.loads(held.read_text(encoding="utf-8"))
    data["status"] = "ok"
    return data


# ---------------------------------------------------------------------------
# Interactive demo & simulation (only when AIDDS_DEMO_MODE=true)
# ---------------------------------------------------------------------------


def _require_demo() -> None:
    if not settings.demo_mode:
        raise HTTPException(status_code=404, detail="demo mode is disabled")


class DemoSimulateRequest(BaseModel):
    scenario: str = "procurement_injection"
    delay_ms: int = Field(default=150, ge=0, le=2000)
    reset_first: bool = True


_DEMO_AGENTS = ["procurement-bot-04", "support-bot-02"]


@app.post("/v1/demo/simulate", tags=["demo"], dependencies=[Depends(require_analyst)])
async def demo_simulate(req: DemoSimulateRequest) -> dict[str, object]:
    """Run a simulated scenario through the live detector pipeline (dashboard demo)."""
    _require_demo()
    from simulator.agents import get_scenario_events

    try:
        events = get_scenario_events(req.scenario)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    if req.reset_first:  # a fresh run of an attack scenario starts from a healthy agent
        agent_ids = {e.agent_id for e in events}
        async with get_session() as session:
            repo = EventRepository(session)
            for a in agent_ids:
                await repo.release_agent(a)
        for a in agent_ids:
            get_tracker().reset_agent(a)

    executed = []
    for evt in events:
        dec = await _process_event(evt)
        executed.append(
            {
                "event_id": str(evt.event_id),
                "tool": evt.tool,
                "data_class": evt.data_class.value,
                "score": dec.score,
                "tier": dec.tier.value,
                "decision": dec.decision.value,
                "alert_id": dec.alert_id,
            }
        )
        if req.delay_ms > 0:
            await asyncio.sleep(req.delay_ms / 1000)

    return {"scenario": req.scenario, "count": len(executed), "events": executed}


@app.post("/v1/demo/reset", tags=["demo"], dependencies=[Depends(require_analyst)])
async def demo_reset() -> dict[str, str]:
    """Reset demo agent state and recent demo events for a clean replay."""
    _require_demo()
    reset_tracker()
    async with get_session() as session:
        repo = EventRepository(session)
        await repo.reset_demo()

    _broadcast_event({"type": "demo_reset"})
    return {"status": "ok", "message": "Demo state reset successfully"}


# ---------------------------------------------------------------------------
# Dashboard static files
# ---------------------------------------------------------------------------

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def serve_dashboard_html() -> Response:
    """Serve the AIDDS Mission Control Dashboard UI."""
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>AIDDS Gateway Active</h1><p>Dashboard files not found.</p>")


@app.get("/index.css", include_in_schema=False)
@app.get("/dashboard/index.css", include_in_schema=False)
async def serve_dashboard_css() -> Response:
    """Serve Dashboard CSS styling."""
    css_file = DASHBOARD_DIR / "index.css"
    if css_file.exists():
        return Response(content=css_file.read_text(encoding="utf-8"), media_type="text/css")
    return Response("", media_type="text/css")


@app.get("/app.js", include_in_schema=False)
@app.get("/dashboard/app.js", include_in_schema=False)
async def serve_dashboard_js() -> Response:
    """Serve Dashboard JavaScript application logic."""
    js_file = DASHBOARD_DIR / "app.js"
    if js_file.exists():
        return Response(
            content=js_file.read_text(encoding="utf-8"), media_type="application/javascript"
        )
    return Response("", media_type="application/javascript")
