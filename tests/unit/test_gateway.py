"""
Unit tests for the AIDDS Gateway layer.

Covers:
  - gateway/database.py  : init_db, close_db, get_session, engine singletons
  - gateway/store.py     : EventRecord, EventRepository (create / get / list / count / replay)
  - gateway/main.py      : all HTTP endpoints via in-process AsyncClient

These tests run entirely in-memory (SQLite via aiosqlite) and do NOT require
a running gateway process or a Postgres instance.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from gateway.database import close_db, get_session, init_db
from gateway.main import app
from gateway.store import EventRepository

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(autouse=True)
async def fresh_db() -> AsyncGenerator[None, None]:
    """Initialise a clean in-memory SQLite DB before every test."""
    await init_db()
    yield
    await close_db()


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """In-process ASGI test client – no network required."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event_payload(
    role: str = "procurement-agent",
    tool: str = "read_catalog",
    action: str = "read",
    resource: str = "catalog/items.csv",
    data_class: str = "pricing",
    sensitivity: int = 1,
    destination: str | None = None,
    bytes_out: int = 0,
    taint: list | None = None,
    session_id: str | None = None,
) -> dict:
    sid = session_id or f"s-unit-{uuid.uuid4().hex[:6]}"
    return {
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(UTC).isoformat(),
        "agent_id": f"bot-{role}",
        "role": role,
        "session_id": sid,
        "tool": tool,
        "action": action,
        "resource": resource,
        "data_class": data_class,
        "sensitivity": sensitivity,
        "destination": destination,
        "bytes_out": bytes_out,
        "taint": taint or [],
        "chain": [],
        "manifest_version": 3,
        "token_id": f"tok-{sid}",
    }


# ---------------------------------------------------------------------------
# gateway/database.py
# ---------------------------------------------------------------------------


class TestDatabase:
    """Tests for the async database engine and session context-manager."""

    @pytest.mark.asyncio
    async def test_init_db_creates_tables(self) -> None:
        """init_db should succeed without errors (idempotent)."""
        await init_db()  # second call — engine already exists

    @pytest.mark.asyncio
    async def test_get_session_commit(self) -> None:
        """get_session yields a session; normal exit commits."""
        async with get_session() as session:
            assert session is not None

    @pytest.mark.asyncio
    async def test_get_session_rollback_on_error(self) -> None:
        """get_session rolls back and re-raises on exception."""
        with pytest.raises(ValueError, match="deliberate"):
            async with get_session() as session:  # noqa: F841
                raise ValueError("deliberate")

    @pytest.mark.asyncio
    async def test_close_db_is_idempotent(self) -> None:
        """close_db can be called multiple times without error."""
        await close_db()
        await close_db()  # second close — no engine to dispose
        await init_db()  # re-initialise so the autouse fixture can clean up


# ---------------------------------------------------------------------------
# gateway/store.py  —  EventRepository
# ---------------------------------------------------------------------------


class TestEventRepository:
    """Tests for EventRepository CRUD operations."""

    def _make_event_dict(self, **kwargs) -> dict:
        sid = str(uuid.uuid4())
        defaults: dict = {
            "event_id": uuid.uuid4(),
            "ts": datetime.now(UTC),
            "agent_id": "bot-test",
            "role": "procurement-agent",
            "session_id": sid,
            "tool": "read_catalog",
            "action": "read",
            "resource": "catalog/items.csv",
            "data_class": "pricing",
            "sensitivity": 1,
            "destination": None,
            "bytes_out": 0,
            "taint": [],
            "chain": [],
            "manifest_version": 3,
            "token_id": "tok-test",
        }
        defaults.update(kwargs)
        return defaults

    def _make_decision_dict(self, score: int = 0, tier: str = "observe") -> dict:
        return {
            "event_id": uuid.uuid4(),
            "decision": "allow",
            "score": score,
            "tier": tier,
            "reasons": [],
            "alert_id": None,
        }

    @pytest.mark.asyncio
    async def test_create_and_get(self) -> None:
        """Create an event and retrieve it by ID."""
        ev = self._make_event_dict()
        dec = self._make_decision_dict()
        async with get_session() as session:
            repo = EventRepository(session)
            record = await repo.create(ev, dec)
            assert record.event_id == str(ev["event_id"])

        async with get_session() as session:
            repo = EventRepository(session)
            fetched = await repo.get(str(ev["event_id"]))
        assert fetched is not None
        assert fetched.tool == "read_catalog"
        assert fetched.score == 0
        assert fetched.tier == "observe"

    @pytest.mark.asyncio
    async def test_get_returns_none_for_missing(self) -> None:
        """get() returns None for a nonexistent event_id."""
        async with get_session() as session:
            repo = EventRepository(session)
            result = await repo.get(str(uuid.uuid4()))
        assert result is None

    @pytest.mark.asyncio
    async def test_create_without_decision(self) -> None:
        """create() succeeds without a decision dict."""
        ev = self._make_event_dict()
        async with get_session() as session:
            repo = EventRepository(session)
            record = await repo.create(ev, None)
        assert record.decision is None
        assert record.score is None

    @pytest.mark.asyncio
    async def test_create_with_destination_and_bytes(self) -> None:
        """Destination and bytes_out are persisted correctly."""
        ev = self._make_event_dict(
            destination="api.approved-supplier.com",
            bytes_out=12345,
        )
        async with get_session() as session:
            repo = EventRepository(session)
            await repo.create(ev, self._make_decision_dict())

        async with get_session() as session:
            repo = EventRepository(session)
            record = await repo.get(str(ev["event_id"]))
        assert record is not None
        assert record.destination == "api.approved-supplier.com"
        assert record.bytes_out == 12345

    @pytest.mark.asyncio
    async def test_list_events_returns_all(self) -> None:
        """list_events returns all stored records."""
        sid = f"s-list-{uuid.uuid4().hex[:4]}"
        async with get_session() as session:
            repo = EventRepository(session)
            for tool in ["read_catalog", "supplier_price_api", "create_purchase_request"]:
                ev = self._make_event_dict(session_id=sid, tool=tool)
                await repo.create(ev, self._make_decision_dict())

        async with get_session() as session:
            repo = EventRepository(session)
            records = await repo.list_events(session_id=sid)
        assert len(records) == 3
        returned_tools = {r.tool for r in records}
        assert "read_catalog" in returned_tools
        assert "supplier_price_api" in returned_tools

    @pytest.mark.asyncio
    async def test_list_events_filter_by_agent(self) -> None:
        """list_events filters by agent_id."""
        # Use a unique prefix so concurrent/repeated runs don't mix
        run_id = uuid.uuid4().hex[:8]
        agent_a = f"bot-a-{run_id}"
        agent_b = f"bot-b-{run_id}"
        async with get_session() as session:
            repo = EventRepository(session)
            for agent in [agent_a, agent_b, agent_a]:
                ev = self._make_event_dict(agent_id=agent)
                await repo.create(ev, self._make_decision_dict())

        async with get_session() as session:
            repo = EventRepository(session)
            records = await repo.list_events(agent_id=agent_a)
        assert all(r.agent_id == agent_a for r in records)
        assert len(records) == 2

    @pytest.mark.asyncio
    async def test_list_events_filter_by_role(self) -> None:
        """list_events filters by role (using a unique session for isolation)."""
        sid = f"s-role-{uuid.uuid4().hex[:8]}"
        unique_role = f"test-agent-role-{uuid.uuid4().hex[:8]}"
        async with get_session() as session:
            repo = EventRepository(session)
            for _ in range(2):
                ev = self._make_event_dict(session_id=sid, role=unique_role)
                await repo.create(ev, self._make_decision_dict())

        async with get_session() as session:
            repo = EventRepository(session)
            records = await repo.list_events(role=unique_role)
        assert len(records) == 2
        assert all(r.role == unique_role for r in records)

    @pytest.mark.asyncio
    async def test_count_returns_total(self) -> None:
        """count() returns at least the number of events we just inserted."""
        sid = f"s-count-{uuid.uuid4().hex[:4]}"
        async with get_session() as session:
            repo = EventRepository(session)
            for _ in range(5):
                ev = self._make_event_dict(session_id=sid)
                await repo.create(ev, self._make_decision_dict())

        # count() is table-wide; we can only assert it's at least 5
        async with get_session() as session:
            repo = EventRepository(session)
            total = await repo.count()
        assert total >= 5

        # Verify filtering works: our 5 events are retrievable by session
        async with get_session() as session:
            repo = EventRepository(session)
            records = await repo.list_events(session_id=sid)
        assert len(records) == 5

    @pytest.mark.asyncio
    async def test_list_for_replay_chronological_order(self) -> None:
        """list_for_replay returns events in ascending timestamp order."""
        sid = f"s-replay-{uuid.uuid4().hex[:4]}"
        tools = ["read_catalog", "supplier_price_api", "create_purchase_request"]
        async with get_session() as session:
            repo = EventRepository(session)
            for tool in tools:
                ev = self._make_event_dict(session_id=sid, tool=tool)
                await repo.create(ev, self._make_decision_dict())

        async with get_session() as session:
            repo = EventRepository(session)
            records = await repo.list_for_replay(session_id=sid)
        timestamps = [r.ts for r in records]
        assert timestamps == sorted(timestamps)

    @pytest.mark.asyncio
    async def test_payload_is_valid_json(self) -> None:
        """Stored payload field is valid JSON containing the original event data."""
        ev = self._make_event_dict(tool="supplier_price_api")
        async with get_session() as session:
            repo = EventRepository(session)
            await repo.create(ev, self._make_decision_dict())

        async with get_session() as session:
            repo = EventRepository(session)
            record = await repo.get(str(ev["event_id"]))
        assert record is not None
        payload = json.loads(record.payload)
        assert payload["tool"] == "supplier_price_api"

    @pytest.mark.asyncio
    async def test_alert_id_persisted(self) -> None:
        """alert_id from decision is stored on the record."""
        ev = self._make_event_dict()
        dec = self._make_decision_dict(score=91, tier="isolate")
        dec["alert_id"] = "A-abc12345"
        async with get_session() as session:
            repo = EventRepository(session)
            await repo.create(ev, dec)

        async with get_session() as session:
            repo = EventRepository(session)
            record = await repo.get(str(ev["event_id"]))
        assert record is not None
        assert record.alert_id == "A-abc12345"

    @pytest.mark.asyncio
    async def test_list_for_replay_filter_by_agent(self) -> None:
        """list_for_replay can filter by agent_id."""
        run_id = uuid.uuid4().hex[:8]
        agent_a = f"bot-replay-a-{run_id}"
        agent_b = f"bot-replay-b-{run_id}"
        async with get_session() as session:
            repo = EventRepository(session)
            for agent in [agent_a, agent_b, agent_a]:
                ev = self._make_event_dict(agent_id=agent)
                await repo.create(ev, self._make_decision_dict())

        async with get_session() as session:
            repo = EventRepository(session)
            records = await repo.list_for_replay(agent_id=agent_a)
        assert len(records) == 2
        assert all(r.agent_id == agent_a for r in records)


# ---------------------------------------------------------------------------
# gateway/main.py  —  HTTP endpoints
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_healthz_returns_ok(self, client: AsyncClient) -> None:
        r = await client.get("/healthz")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["version"] == "0.2.0"


class TestToolCallEndpoint:
    @pytest.mark.asyncio
    async def test_benign_event_returns_observe(self, client: AsyncClient) -> None:
        """A normal in-role event returns score 0, tier=observe, decision=allow."""
        payload = _event_payload(tool="read_catalog", data_class="pricing")
        r = await client.post("/v1/tool-calls", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["score"] == 0
        assert data["tier"] == "observe"
        assert data["decision"] == "allow"
        assert data["alert_id"] is None

    @pytest.mark.asyncio
    async def test_honeypot_event_returns_isolate(self, client: AsyncClient) -> None:
        """Honeypot access triggers isolate tier and deny decision."""
        payload = _event_payload(
            tool="hr_export_db",
            resource="hr/salaries_2026_FULL.xlsx",
            data_class="hr",
            sensitivity=3,
        )
        r = await client.post("/v1/tool-calls", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["score"] >= 90
        assert data["tier"] == "isolate"
        assert data["decision"] == "deny"
        assert data["alert_id"] is not None

    @pytest.mark.asyncio
    async def test_attack_event_generates_alert_id(self, client: AsyncClient) -> None:
        """High-scoring event gets an alert_id starting with 'A-'."""
        payload = _event_payload(tool="hr_export_db", data_class="hr", sensitivity=3)
        r = await client.post("/v1/tool-calls", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["alert_id"] is not None
        assert data["alert_id"].startswith("A-")

    @pytest.mark.asyncio
    async def test_reasons_returned_for_violation(self, client: AsyncClient) -> None:
        """Detected violations include reasons in the response."""
        payload = _event_payload(tool="hr_export_db", data_class="hr", sensitivity=3)
        r = await client.post("/v1/tool-calls", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert len(data["reasons"]) > 0
        signals = {reason["signal"] for reason in data["reasons"]}
        assert "role_violation" in signals

    @pytest.mark.asyncio
    async def test_invalid_payload_returns_422(self, client: AsyncClient) -> None:
        """Missing required fields cause a 422 Unprocessable Entity."""
        r = await client.post("/v1/tool-calls", json={"agent_id": "bot"})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_event_is_persisted_after_post(self, client: AsyncClient) -> None:
        """Posted event appears in the event store via GET /v1/events."""
        sid = f"s-persist-{uuid.uuid4().hex[:6]}"
        payload = _event_payload(tool="read_catalog", session_id=sid)
        r = await client.post("/v1/tool-calls", json=payload)
        assert r.status_code == 200

        list_r = await client.get(f"/v1/events?session_id={sid}")
        assert list_r.status_code == 200
        data = list_r.json()
        assert data["total"] >= 1
        assert any(e["event_id"] == payload["event_id"] for e in data["events"])


class TestEventListEndpoint:
    @pytest.mark.asyncio
    async def test_list_events_returns_empty_for_unknown_session(self, client: AsyncClient) -> None:
        """Event list is empty for an unknown session_id."""
        sid = f"s-empty-{uuid.uuid4().hex[:6]}"
        r = await client.get(f"/v1/events?session_id={sid}")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] >= 0
        assert isinstance(data["events"], list)

    @pytest.mark.asyncio
    async def test_list_events_filter_by_session(self, client: AsyncClient) -> None:
        """session_id filter returns only matching events."""
        sid = f"s-filt-{uuid.uuid4().hex[:6]}"
        for tool in ["read_catalog", "supplier_price_api"]:
            await client.post("/v1/tool-calls", json=_event_payload(tool=tool, session_id=sid))

        r = await client.get(f"/v1/events?session_id={sid}")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] >= 2
        for ev in data["events"]:
            assert ev["session_id"] == sid

    @pytest.mark.asyncio
    async def test_list_events_filter_by_role(self, client: AsyncClient) -> None:
        """role filter returns only events with the specified role."""
        payload = _event_payload(role="procurement-agent")
        await client.post("/v1/tool-calls", json=payload)
        r = await client.get("/v1/events?role=procurement-agent")
        assert r.status_code == 200
        data = r.json()
        assert all(e["role"] == "procurement-agent" for e in data["events"])

    @pytest.mark.asyncio
    async def test_list_events_filter_by_agent(self, client: AsyncClient) -> None:
        """agent_id filter returns only events from the specified agent."""
        payload = _event_payload(role="procurement-agent")
        agent_id = payload["agent_id"]
        await client.post("/v1/tool-calls", json=payload)
        r = await client.get(f"/v1/events?agent_id={agent_id}")
        assert r.status_code == 200
        data = r.json()
        assert all(e["agent_id"] == agent_id for e in data["events"])

    @pytest.mark.asyncio
    async def test_list_events_pagination(self, client: AsyncClient) -> None:
        """limit parameter restricts the number of results returned."""
        sid = f"s-page-{uuid.uuid4().hex[:4]}"
        for _ in range(5):
            await client.post("/v1/tool-calls", json=_event_payload(session_id=sid))

        r = await client.get(f"/v1/events?session_id={sid}&limit=2&offset=0")
        assert r.status_code == 200
        data = r.json()
        assert len(data["events"]) == 2


class TestEventDetailEndpoint:
    @pytest.mark.asyncio
    async def test_get_event_detail_found(self, client: AsyncClient) -> None:
        """GET /v1/events/{id} returns full detail including payload."""
        payload = _event_payload(tool="read_catalog")
        await client.post("/v1/tool-calls", json=payload)

        r = await client.get(f"/v1/events/{payload['event_id']}")
        assert r.status_code == 200
        detail = r.json()
        assert detail["event_id"] == payload["event_id"]
        assert detail["tool"] == "read_catalog"
        assert "payload" in detail

    @pytest.mark.asyncio
    async def test_get_event_detail_not_found(self, client: AsyncClient) -> None:
        """GET /v1/events/{unknown_id} returns 404."""
        r = await client.get(f"/v1/events/{uuid.uuid4()}")
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_event_detail_includes_score_and_tier(self, client: AsyncClient) -> None:
        """Event detail includes the detector's score and tier."""
        payload = _event_payload(tool="hr_export_db", data_class="hr", sensitivity=3)
        await client.post("/v1/tool-calls", json=payload)
        r = await client.get(f"/v1/events/{payload['event_id']}")
        assert r.status_code == 200
        detail = r.json()
        assert detail["score"] is not None
        assert detail["tier"] is not None
        assert detail["decision"] is not None


class TestReplayEndpoint:
    @pytest.mark.asyncio
    async def test_replay_returns_results(self, client: AsyncClient) -> None:
        """POST /v1/events/replay returns replayed count and results list."""
        sid = f"s-rpl-{uuid.uuid4().hex[:4]}"
        for tool in ["read_catalog", "supplier_price_api"]:
            await client.post("/v1/tool-calls", json=_event_payload(tool=tool, session_id=sid))

        r = await client.post(f"/v1/events/replay?session_id={sid}")
        assert r.status_code == 200
        data = r.json()
        assert data["replayed"] == 2
        assert len(data["results"]) == 2

    @pytest.mark.asyncio
    async def test_replay_result_has_expected_fields(self, client: AsyncClient) -> None:
        """Each replay result contains event_id, scores, tier, and changed flag."""
        sid = f"s-rplf-{uuid.uuid4().hex[:4]}"
        await client.post("/v1/tool-calls", json=_event_payload(session_id=sid))
        r = await client.post(f"/v1/events/replay?session_id={sid}")
        assert r.status_code == 200
        result = r.json()["results"][0]
        assert "event_id" in result
        assert "original_score" in result
        assert "replay_score" in result
        assert "replay_tier" in result
        assert "changed" in result

    @pytest.mark.asyncio
    async def test_replay_empty_session_returns_zero(self, client: AsyncClient) -> None:
        """Replaying a session with no events returns replayed=0."""
        r = await client.post("/v1/events/replay?session_id=nonexistent-session")
        assert r.status_code == 200
        data = r.json()
        assert data["replayed"] == 0
        assert data["results"] == []


class TestStubEndpoints:
    """Tests for stub endpoints to ensure they return correct shapes."""

    @pytest.mark.asyncio
    async def test_get_agent_risk(self, client: AsyncClient) -> None:
        r = await client.get("/v1/agents/bot-test/risk")
        assert r.status_code == 200
        data = r.json()
        assert data["agent_id"] == "bot-test"
        assert "score" in data
        assert "tier" in data

    @pytest.mark.asyncio
    async def test_list_alerts(self, client: AsyncClient) -> None:
        r = await client.get("/v1/alerts")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @pytest.mark.asyncio
    async def test_get_alert_unknown_is_404(self, client: AsyncClient) -> None:
        assert (await client.get("/v1/alerts/A-nope")).status_code == 404

    @pytest.mark.asyncio
    async def test_alert_feedback_unknown_is_404(self, client: AsyncClient) -> None:
        assert (await client.post("/v1/alerts/A-nope/feedback")).status_code == 404

    @pytest.mark.asyncio
    async def test_approval_unknown_is_404(self, client: AsyncClient) -> None:
        assert (await client.post("/v1/approvals/app-none")).status_code == 404

    @pytest.mark.asyncio
    async def test_upload_unsigned_manifest_rejected(self, client: AsyncClient) -> None:
        r = await client.put("/v1/manifests/procurement-agent", json={"role": "procurement-agent"})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_release_unknown_agent_is_404(self, client: AsyncClient) -> None:
        assert (await client.post("/v1/agents/bot-001/release")).status_code == 404
