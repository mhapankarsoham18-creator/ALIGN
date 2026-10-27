"""
Integration tests for the AIDDS Gateway & Detector pipeline.

Tests end-to-end HTTP requests against the FastAPI gateway app,
verifying event interception, detector scoring, SQLite persistence,
filtering, detail lookup, and replay.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from gateway.database import close_db, init_db
from gateway.main import app


@pytest_asyncio.fixture(autouse=True)
async def setup_test_db() -> AsyncGenerator[None, None]:
    """Initialize DB before tests and clean up after."""
    await init_db()
    yield
    await close_db()


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """Async test client using ASGITransport."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as ac:
        yield ac


def _make_event_payload(
    role: str = "procurement-agent",
    tool: str = "read_catalog",
    action: str = "read",
    resource: str = "catalog/items.csv",
    data_class: str = "pricing",
    sensitivity: int = 1,
    destination: str | None = None,
    bytes_out: int = 0,
    taint: list[dict[str, str]] | None = None,
    session_id: str | None = None,
) -> dict[str, object]:
    """Helper to build a valid tool call event payload."""
    sid = session_id or f"s-int-{uuid.uuid4().hex[:6]}"
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


@pytest.mark.asyncio
async def test_healthz(client: AsyncClient) -> None:
    """Test health check endpoint."""
    response = await client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "0.2.0"


@pytest.mark.asyncio
async def test_normal_procurement_tool_call(client: AsyncClient) -> None:
    """A benign tool call receives score 0, observe tier, and allow decision."""
    payload = _make_event_payload(
        role="procurement-agent",
        tool="read_catalog",
        action="read",
        data_class="pricing",
    )
    response = await client.post("/v1/tool-calls", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["score"] == 0
    assert data["tier"] == "observe"
    assert data["decision"] == "allow"
    assert data["alert_id"] is None


@pytest.mark.asyncio
async def test_honeypot_triggers_isolation(client: AsyncClient) -> None:
    """Touching a honeypot triggers immediate isolation (score 95+, deny)."""
    payload = _make_event_payload(
        role="procurement-agent",
        tool="hr_export_db",
        action="read",
        resource="hr/salaries_2026_FULL.xlsx",
        data_class="hr",
        sensitivity=3,
    )
    response = await client.post("/v1/tool-calls", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["score"] >= 90
    assert data["tier"] == "isolate"
    assert data["decision"] == "deny"
    assert data["alert_id"] is not None
    assert any("honeypot" in r["signal"] for r in data["reasons"])


@pytest.mark.asyncio
async def test_list_and_get_events(client: AsyncClient) -> None:
    """Events can be listed and retrieved by ID."""
    session_id = f"s-query-{uuid.uuid4().hex[:6]}"
    payload = _make_event_payload(
        role="procurement-agent",
        tool="supplier_price_api",
        session_id=session_id,
    )
    post_res = await client.post("/v1/tool-calls", json=payload)
    assert post_res.status_code == 200

    # Query events by session_id
    list_res = await client.get(f"/v1/events?session_id={session_id}")
    assert list_res.status_code == 200
    events_data = list_res.json()
    assert events_data["total"] >= 1
    found = [e for e in events_data["events"] if e["event_id"] == payload["event_id"]]
    assert len(found) == 1
    assert found[0]["tool"] == "supplier_price_api"

    # Get single event detail
    detail_res = await client.get(f"/v1/events/{payload['event_id']}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["event_id"] == payload["event_id"]
    assert detail["tool"] == "supplier_price_api"
    assert "payload" in detail
