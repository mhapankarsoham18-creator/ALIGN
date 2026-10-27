"""
AIDDS Gateway — Event store: SQLAlchemy model + async repository.

Every tool call is persisted as an EventRecord. The repository supports
create, get, list (with filters), and replay.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Integer, String, Text, delete, desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ---------------------------------------------------------------------------
# ORM base
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Base class for all AIDDS ORM models."""

    pass


# ---------------------------------------------------------------------------
# EventRecord model
# ---------------------------------------------------------------------------


class EventRecord(Base):
    """
    Persisted tool-call event.

    Stores the full event payload as JSON alongside indexed columns
    used for queries, filtering, and replay.
    """

    __tablename__ = "events"

    # Primary key — the event UUID as a string
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)

    # Indexed query columns
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    session_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    tool: Mapped[str] = mapped_column(String(256), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    resource: Mapped[str] = mapped_column(String(512), nullable=False)
    data_class: Mapped[str] = mapped_column(String(64), nullable=False)
    sensitivity: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    destination: Mapped[str | None] = mapped_column(String(256), nullable=True)
    bytes_out: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Full event JSON — includes taint, chain, manifest_version, token_id
    payload: Mapped[str] = mapped_column(Text, nullable=False)

    # Decision returned by the detector
    decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tier: Mapped[str | None] = mapped_column(String(16), nullable=True)
    alert_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Timestamp when the record was created in the store
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# AlertRecord model
# ---------------------------------------------------------------------------


class AlertRecord(Base):
    """
    Persisted security alert triggered by identity drift or malicious action.
    """

    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    session_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    tier: Mapped[str] = mapped_column(String(16), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    tool: Mapped[str] = mapped_column(String(256), nullable=False)
    resource: Mapped[str] = mapped_column(String(512), nullable=False)
    reasons_json: Mapped[str] = mapped_column(Text, nullable=False)
    feedback: Mapped[str] = mapped_column(String(32), default="unreviewed")
    status: Mapped[str] = mapped_column(String(32), default="open")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# AgentStateRecord model
# ---------------------------------------------------------------------------


class AgentStateRecord(Base):
    """
    Current live runtime state, risk posture, and containment status of an agent.
    """

    __tablename__ = "agent_states"

    agent_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    role: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="healthy")
    score: Mapped[int] = mapped_column(Integer, default=0)
    tier: Mapped[str] = mapped_column(String(16), default="observe")
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    is_tainted: Mapped[bool] = mapped_column(Boolean, default=False)
    last_event_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# ApprovalRecord model
# ---------------------------------------------------------------------------


class ApprovalRecord(Base):
    """
    Human approval requests for actions paused in the step-up tier.
    """

    __tablename__ = "approvals"

    approval_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# AuditRecord model (append-only trail of privileged actions)
# ---------------------------------------------------------------------------


class AuditRecord(Base):
    """Who did what: manifest changes, approvals, releases, feedback. Never updated or deleted."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC), index=True
    )
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")


# ---------------------------------------------------------------------------
# EventRepository — async CRUD
# ---------------------------------------------------------------------------


class EventRepository:
    """Async operations on events, alerts, and agent states."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        event_dict: dict[str, Any],
        decision_dict: dict[str, Any] | None = None,
    ) -> EventRecord:
        """
        Persist a tool-call event and its decision, and update alert/agent state.
        """
        raw_ts = event_dict.get("ts")
        if isinstance(raw_ts, str):
            ts_val: datetime | None = datetime.fromisoformat(raw_ts)
        elif isinstance(raw_ts, datetime):
            ts_val = raw_ts
        else:
            ts_val = datetime.now(UTC)

        record = EventRecord(
            event_id=str(event_dict["event_id"]),
            ts=ts_val,
            agent_id=str(event_dict["agent_id"]),
            role=str(event_dict["role"]),
            session_id=str(event_dict["session_id"]),
            tool=str(event_dict["tool"]),
            action=str(event_dict["action"]),
            resource=str(event_dict["resource"]),
            data_class=str(event_dict["data_class"]),
            sensitivity=int(event_dict.get("sensitivity") or 0),
            destination=str(event_dict["destination"]) if event_dict.get("destination") else None,
            bytes_out=int(event_dict.get("bytes_out") or 0),
            payload=json.dumps(event_dict, default=str),
        )

        score = 0
        tier = "observe"
        decision_verb = "allow"
        alert_id: str | None = None

        if decision_dict:
            dec_val = decision_dict.get("decision", "allow")
            decision_verb = (
                dec_val.value
                if hasattr(dec_val, "value")
                else str(dec_val).lower().replace("decisionverb.", "")
            )

            score = int(decision_dict.get("score") or 0)

            tier_val = decision_dict.get("tier", "observe")
            tier = (
                tier_val.value
                if hasattr(tier_val, "value")
                else str(tier_val).lower().replace("tier.", "")
            )

            raw_alert_id = decision_dict.get("alert_id")
            alert_id = str(raw_alert_id) if raw_alert_id else None

            record.decision = decision_verb
            record.score = score
            record.tier = tier
            record.alert_id = alert_id

            if alert_id:
                reasons = decision_dict.get("reasons") or []
                reasons_serializable = []
                if isinstance(reasons, list):
                    for r in reasons:
                        if hasattr(r, "model_dump"):
                            reasons_serializable.append(r.model_dump())
                        elif isinstance(r, dict):
                            reasons_serializable.append(r)
                        else:
                            reasons_serializable.append(
                                {"signal": "unknown", "points": 0, "text": str(r)}
                            )

                alert_rec = await self._session.get(AlertRecord, str(alert_id))
                if alert_rec is None:
                    alert_rec = AlertRecord(
                        alert_id=str(alert_id),
                        event_id=record.event_id,
                        agent_id=record.agent_id,
                        role=record.role,
                        session_id=record.session_id,
                        ts=record.ts,
                        score=score,
                        tier=tier,
                        decision=decision_verb,
                        tool=record.tool,
                        resource=record.resource,
                        reasons_json=json.dumps(reasons_serializable),
                        feedback="unreviewed",
                        status="open",
                    )
                    self._session.add(alert_rec)
                else:
                    alert_rec.event_id = record.event_id
                    alert_rec.agent_id = record.agent_id
                    alert_rec.role = record.role
                    alert_rec.session_id = record.session_id
                    alert_rec.ts = record.ts
                    alert_rec.score = score
                    alert_rec.tier = tier
                    alert_rec.decision = decision_verb
                    alert_rec.tool = record.tool
                    alert_rec.resource = record.resource
                    alert_rec.reasons_json = json.dumps(reasons_serializable)

        self._session.add(record)

        # Update Agent State
        has_taint = bool(event_dict.get("taint"))
        agent_id = str(event_dict["agent_id"])
        agent_state = await self._session.get(AgentStateRecord, agent_id)

        if agent_state is None:
            status_val = "healthy"
            if tier == "isolate":
                status_val = "isolated"
            elif tier == "restrict":
                status_val = "restricted"
            elif tier == "step_up":
                status_val = "step_up"

            agent_state = AgentStateRecord(
                agent_id=agent_id,
                role=str(event_dict["role"]),
                status=status_val,
                score=score,
                tier=tier,
                event_count=1,
                is_tainted=has_taint,
                last_event_ts=ts_val,
            )
            self._session.add(agent_state)
        else:
            agent_state.event_count += 1
            agent_state.last_event_ts = ts_val
            if has_taint:
                agent_state.is_tainted = True

            # If isolated, remain isolated until explicit release
            if agent_state.status != "isolated":
                if tier == "isolate":
                    agent_state.status = "isolated"
                    agent_state.score = score
                    agent_state.tier = tier
                elif score >= agent_state.score:
                    agent_state.score = score
                    agent_state.tier = tier
                    if tier == "restrict":
                        agent_state.status = "restricted"
                    elif tier == "step_up":
                        agent_state.status = "step_up"
                    else:
                        agent_state.status = "healthy"
            else:
                agent_state.score = max(agent_state.score, score)

        await self._session.flush()
        return record

    async def get(self, event_id: str) -> EventRecord | None:
        """Fetch a single event by ID."""
        return await self._session.get(EventRecord, event_id)

    async def list_events(
        self,
        agent_id: str | None = None,
        role: str | None = None,
        session_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[EventRecord]:
        """List events with optional filters, newest first."""
        stmt = select(EventRecord).order_by(desc(EventRecord.ts))

        if agent_id:
            stmt = stmt.where(EventRecord.agent_id == agent_id)
        if role:
            stmt = stmt.where(EventRecord.role == role)
        if session_id:
            stmt = stmt.where(EventRecord.session_id == session_id)

        stmt = stmt.limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def count(self) -> int:
        """Return total number of stored events."""
        from sqlalchemy import func

        stmt = select(func.count()).select_from(EventRecord)
        result = await self._session.execute(stmt)
        return result.scalar_one()

    async def list_for_replay(
        self,
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> Sequence[EventRecord]:
        """Return events in chronological order for replay."""
        stmt = select(EventRecord).order_by(EventRecord.ts)

        if session_id:
            stmt = stmt.where(EventRecord.session_id == session_id)
        if agent_id:
            stmt = stmt.where(EventRecord.agent_id == agent_id)

        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def get_agent_state(self, agent_id: str) -> AgentStateRecord | None:
        """Get the current state for an agent."""
        return await self._session.get(AgentStateRecord, agent_id)

    async def list_agent_states(self) -> Sequence[AgentStateRecord]:
        """List all tracked agents and their states."""
        stmt = select(AgentStateRecord).order_by(AgentStateRecord.agent_id)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def release_agent(self, agent_id: str) -> AgentStateRecord | None:
        """Lift isolation/restriction for an agent and restore to healthy/observe."""
        state = await self._session.get(AgentStateRecord, agent_id)
        if state is not None:
            state.status = "healthy"
            state.score = 0
            state.tier = "observe"
            state.is_tainted = False
            state.updated_at = datetime.now(UTC)
            await self._session.flush()
        return state

    async def list_alerts(
        self,
        alert_status: str | None = None,
        tier: str | None = None,
        limit: int = 100,
    ) -> Sequence[AlertRecord]:
        """List alerts newest first with optional status or tier filters."""
        stmt = select(AlertRecord).order_by(desc(AlertRecord.ts))
        if alert_status:
            stmt = stmt.where(AlertRecord.status == alert_status)
        if tier:
            stmt = stmt.where(AlertRecord.tier == tier)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def get_alert(self, alert_id: str) -> AlertRecord | None:
        """Get an alert by ID."""
        return await self._session.get(AlertRecord, alert_id)

    async def update_alert_feedback(self, alert_id: str, feedback: str) -> AlertRecord | None:
        """Update analyst feedback (e.g. 'false_alarm' or 'confirmed')."""
        alert = await self._session.get(AlertRecord, alert_id)
        if alert is not None:
            alert.feedback = feedback
            alert.status = "reviewed"
            await self._session.flush()
        return alert

    async def create_or_update_approval(
        self,
        approval_id: str,
        agent_id: str = "unknown",
        action_type: str = "tool_call",
        resource: str = "",
        status: str = "approved",
    ) -> ApprovalRecord:
        """Create or update a human step-up approval."""
        approval = await self._session.get(ApprovalRecord, approval_id)
        if approval is None:
            approval = ApprovalRecord(
                approval_id=approval_id,
                agent_id=agent_id,
                action_type=action_type,
                resource=resource,
                status=status,
            )
            self._session.add(approval)
        else:
            approval.status = status
        await self._session.flush()
        return approval

    # -- identity ---------------------------------------------------------

    async def get_agent_role(self, agent_id: str) -> str | None:
        """Role the agent was first seen with (first-seen binding), if any."""
        state = await self._session.get(AgentStateRecord, agent_id)
        return state.role if state is not None else None

    # -- approvals --------------------------------------------------------

    async def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        return await self._session.get(ApprovalRecord, approval_id)

    async def list_approvals(
        self, status: str | None = None, limit: int = 100
    ) -> Sequence[ApprovalRecord]:
        stmt = select(ApprovalRecord).order_by(desc(ApprovalRecord.created_at))
        if status:
            stmt = stmt.where(ApprovalRecord.status == status)
        result = await self._session.execute(stmt.limit(limit))
        return result.scalars().all()

    async def find_approval(
        self, agent_id: str, tool: str, resource: str, status: str
    ) -> ApprovalRecord | None:
        stmt = (
            select(ApprovalRecord)
            .where(
                ApprovalRecord.agent_id == agent_id,
                ApprovalRecord.action_type == tool,
                ApprovalRecord.resource == resource,
                ApprovalRecord.status == status,
            )
            .order_by(desc(ApprovalRecord.created_at))
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalars().first()

    async def create_pending_approval(
        self, approval_id: str, agent_id: str, tool: str, resource: str
    ) -> ApprovalRecord:
        existing = await self.find_approval(agent_id, tool, resource, "pending")
        if existing is not None:
            return existing
        rec = ApprovalRecord(
            approval_id=approval_id,
            agent_id=agent_id,
            action_type=tool,
            resource=resource,
            status="pending",
        )
        self._session.add(rec)
        await self._session.flush()
        return rec

    async def decide_approval(self, approval_id: str, status: str) -> ApprovalRecord | None:
        rec = await self._session.get(ApprovalRecord, approval_id)
        if rec is None or rec.status != "pending":
            return rec
        rec.status = status
        await self._session.flush()
        return rec

    async def consume_approval(self, rec: ApprovalRecord) -> None:
        rec.status = "consumed"
        await self._session.flush()

    # -- audit ------------------------------------------------------------

    async def add_audit(self, actor: str, action: str, target: str = "", detail: str = "") -> None:
        self._session.add(
            AuditRecord(actor=actor, action=action, target=target[:256], detail=detail[:2000])
        )
        await self._session.flush()

    async def list_audit(self, limit: int = 200) -> Sequence[AuditRecord]:
        stmt = select(AuditRecord).order_by(desc(AuditRecord.id)).limit(limit)
        return (await self._session.execute(stmt)).scalars().all()

    async def reset_demo(self) -> None:
        """Reset demo events, alerts, and agent states for clean rehearsal."""
        demo_agents = ["procurement-bot-04", "support-bot-02"]
        # Delete demo events
        for agent in demo_agents:
            await self._session.execute(delete(EventRecord).where(EventRecord.agent_id == agent))
            await self._session.execute(delete(AlertRecord).where(AlertRecord.agent_id == agent))
            await self._session.execute(
                delete(ApprovalRecord).where(ApprovalRecord.agent_id == agent)
            )
            await self._session.execute(
                delete(AgentStateRecord).where(AgentStateRecord.agent_id == agent)
            )
        await self._session.flush()
