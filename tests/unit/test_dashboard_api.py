"""
Unit tests for the Phase 6 Dashboard, Simulation, and Alert Management APIs.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from gateway.database import close_db, init_db
from gateway.main import app


@pytest_asyncio.fixture(autouse=True)
async def fresh_db():
    await init_db()
    yield
    await close_db()


@pytest_asyncio.fixture
async def client() -> AsyncClient:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_dashboard_static_endpoints(client: AsyncClient) -> None:
    """Verify that root, dashboard html, css, and js are served."""
    r_root = await client.get("/")
    assert r_root.status_code == 200
    assert "AIDDS" in r_root.text

    r_dash = await client.get("/dashboard")
    assert r_dash.status_code == 200
    assert "AIDDS" in r_dash.text

    r_css = await client.get("/index.css")
    assert r_css.status_code == 200
    assert "--bg-base" in r_css.text

    r_js = await client.get("/app.js")
    assert r_js.status_code == 200
    assert "AIDDS Mission Control Dashboard" in r_js.text


@pytest.mark.asyncio
async def test_list_agents_endpoint(client: AsyncClient) -> None:
    """Verify that GET /v1/agents returns tracked agents with default posture."""
    r = await client.get("/v1/agents")
    assert r.status_code == 200
    agents = r.json()
    assert isinstance(agents, list)
    agent_ids = [a["agent_id"] for a in agents]
    assert "procurement-bot-04" in agent_ids
    assert "support-bot-02" in agent_ids


@pytest.mark.asyncio
async def test_demo_simulation_and_reset(client: AsyncClient) -> None:
    """Verify that POST /v1/demo/simulate runs a scenario and /v1/demo/reset clears it."""
    # Run normal procurement work
    r_sim = await client.post(
        "/v1/demo/simulate", json={"scenario": "normal_procurement", "delay_ms": 0}
    )
    assert r_sim.status_code == 200
    data = r_sim.json()
    assert data["scenario"] == "normal_procurement"
    assert data["count"] > 0
    assert len(data["events"]) == data["count"]

    # Check that agents list now shows events for procurement-bot-04
    r_agents = await client.get("/v1/agents")
    assert r_agents.status_code == 200
    proc = next(a for a in r_agents.json() if a["agent_id"] == "procurement-bot-04")
    assert proc["event_count"] >= data["count"]

    # Reset demo
    r_reset = await client.post("/v1/demo/reset")
    assert r_reset.status_code == 200
    assert r_reset.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_eval_metrics_endpoint(client: AsyncClient) -> None:
    """Verify GET /v1/eval/metrics returns report data."""
    r = await client.get("/v1/eval/metrics")
    assert r.status_code == 200
    data = r.json()
    assert "results" in data
    assert "recall" in data["results"]
    assert "false_positive_rate" in data["results"]


@pytest.mark.asyncio
async def test_alert_lifecycle_and_feedback(client: AsyncClient) -> None:
    """Verify full alert generation from honeypot attack and analyst feedback."""
    # Trigger honeypot attack
    r_sim = await client.post("/v1/demo/simulate", json={"scenario": "honeypot", "delay_ms": 0})
    assert r_sim.status_code == 200

    # List alerts
    r_alerts = await client.get("/v1/alerts")
    assert r_alerts.status_code == 200
    alerts = r_alerts.json()
    assert len(alerts) > 0
    target_alert = alerts[0]
    alert_id = target_alert["alert_id"]

    # Get alert detail
    r_detail = await client.get(f"/v1/alerts/{alert_id}")
    assert r_detail.status_code == 200
    assert r_detail.json()["alert_id"] == alert_id
    assert r_detail.json()["score"] >= 90

    # Record analyst feedback
    r_fb = await client.post(f"/v1/alerts/{alert_id}/feedback", json={"feedback": "confirmed"})
    assert r_fb.status_code == 200
    assert r_fb.json()["feedback"] == "confirmed"

    # Verify agent release
    r_rel = await client.post(f"/v1/agents/{target_alert['agent_id']}/release")
    assert r_rel.status_code == 200
    assert r_rel.json()["status"] == "released"
