"""Gateway behaviour added in v0.2: auth, enforcement, approvals, signed manifests, routing."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
import yaml
from httpx import ASGITransport, AsyncClient

from detector.manifest_loader import get_manifest, reload_manifests
from gateway.config import settings
from gateway.database import close_db, init_db
from gateway.main import app


@pytest_asyncio.fixture(autouse=True)
async def fresh_db() -> AsyncGenerator[None, None]:
    await init_db()
    yield
    await close_db()


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        yield ac


def _evt(
    agent="procurement-bot-04",
    role="procurement-agent",
    tool="read_catalog",
    action="read",
    resource="catalog/items.csv",
    data_class="pricing",
    sens=1,
    dest=None,
    bytes_out=0,
    sid="s1",
    **extra,
):
    return {
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(UTC).isoformat(),
        "agent_id": agent,
        "role": role,
        "session_id": sid,
        "tool": tool,
        "action": action,
        "resource": resource,
        "data_class": data_class,
        "sensitivity": sens,
        "destination": dest,
        "bytes_out": bytes_out,
        "taint": [],
        "chain": [],
        "manifest_version": 3,
        "token_id": "t",
        **extra,
    }


HONEYPOT = dict(tool="hr_export_db", resource="hr/salaries_2026_FULL.xlsx", data_class="hr", sens=3)


def test_stream_route_declared_before_event_id_route() -> None:
    paths = [getattr(r, "path", "") for r in app.routes]
    assert paths.index("/v1/events/stream") < paths.index("/v1/events/{event_id}")


@pytest.mark.asyncio
async def test_gateway_key_required_when_configured(client: AsyncClient, monkeypatch) -> None:
    monkeypatch.setattr(settings, "gateway_api_key", "gk")
    assert (await client.post("/v1/tool-calls", json=_evt())).status_code == 401
    r = await client.post("/v1/tool-calls", json=_evt(), headers={"X-Gateway-Key": "gk"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_analyst_key_protects_read_endpoints(client: AsyncClient, monkeypatch) -> None:
    monkeypatch.setattr(settings, "analyst_api_key", "ak")
    assert (await client.get("/v1/alerts")).status_code == 401
    assert (await client.get("/v1/alerts", headers={"X-API-Key": "ak"})).status_code == 200
    assert (await client.get("/healthz")).status_code == 200  # probes stay open


@pytest.mark.asyncio
async def test_isolated_agent_is_denied_afterwards(client: AsyncClient) -> None:
    r = await client.post("/v1/tool-calls", json=_evt(**HONEYPOT))
    assert r.json()["tier"] == "isolate"
    r2 = await client.post("/v1/tool-calls", json=_evt(sid="s2"))
    assert r2.json()["decision"] == "deny"
    assert r2.json()["reasons"][0]["signal"] == "agent_isolated"
    # analyst releases -> works again
    assert (await client.post("/v1/agents/procurement-bot-04/release")).status_code == 200
    r3 = await client.post("/v1/tool-calls", json=_evt(sid="s3"))
    assert r3.json()["decision"] == "allow"


@pytest.mark.asyncio
async def test_identity_mismatch_uses_registry_role(client: AsyncClient) -> None:
    r = await client.post(
        "/v1/tool-calls",
        json=_evt(
            role="hr-assistant-agent",
            tool="hr_export_db",
            resource="hr/x.csv",
            data_class="hr",
            sens=3,
        ),
    )
    signals = {x["signal"] for x in r.json()["reasons"]}
    assert "identity_mismatch" in signals
    assert r.json()["tier"] != "observe"


@pytest.mark.asyncio
async def test_step_up_creates_approval_and_approval_releases_once(client: AsyncClient) -> None:
    ev = dict(
        tool="send_email",
        action="write",
        resource="mail/out",
        data_class="pricing",
        sens=2,
        dest="partner.example.com",
        bytes_out=1000,
    )
    d = (await client.post("/v1/tool-calls", json=_evt(**ev))).json()
    if d["tier"] != "step_up":
        pytest.skip(f"scenario not step_up under current manifest (tier={d['tier']})")
    pending = (await client.get("/v1/approvals?status=pending")).json()
    assert pending
    aid = pending[0]["approval_id"]
    assert (
        await client.post(f"/v1/approvals/{aid}", json={"status": "approved"})
    ).status_code == 200
    assert (await client.post(f"/v1/approvals/{aid}", json={"status": "denied"})).status_code == 409
    d2 = (await client.post("/v1/tool-calls", json=_evt(sid="s9", **ev))).json()
    assert d2["decision"] == "allow"
    assert any(x["signal"] == "human_approval" for x in d2["reasons"])


@pytest.mark.asyncio
async def test_manifest_put_requires_valid_signature(client: AsyncClient) -> None:
    cur = get_manifest("procurement-agent")
    assert cur is not None
    body = cur.model_dump(mode="json")
    body["version"] = cur.version + 1  # signature no longer matches
    r = await client.put("/v1/manifests/procurement-agent", json=body)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_manifest_put_signed_roundtrip(client: AsyncClient, tmp_path, monkeypatch) -> None:
    import json

    from detector.schemas import RoleManifest
    from detector.signing import generate_keypair, sign_manifest

    key_id = "testkey"
    priv, pub = generate_keypair()
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({"keys": {key_id: pub}}))
    mdir = tmp_path / "manifests"
    mdir.mkdir()
    monkeypatch.setattr(settings, "trusted_keys_file", str(keys))
    monkeypatch.setattr(settings, "manifests_dir", str(mdir))
    reload_manifests()
    try:
        m = RoleManifest(
            role="demo-role", version=1, owner="t", description="d", allowed_tools=["read_catalog"]
        )
        m.signature = sign_manifest(m, key_id, priv)
        body = m.model_dump(mode="json")
        assert (await client.put("/v1/manifests/demo-role", json=body)).status_code == 200
        assert (
            await client.put("/v1/manifests/demo-role", json=body)
        ).status_code == 409  # not newer
        assert (
            await client.put("/v1/manifests/other", json=body)
        ).status_code == 400  # url/body mismatch
        assert yaml.safe_load((mdir / "demo-role.yaml").read_text())["role"] == "demo-role"
        audit = (await client.get("/v1/audit")).json()
        assert any(a["action"] == "manifest.install" for a in audit)
    finally:
        monkeypatch.undo()
        reload_manifests()


@pytest.mark.asyncio
async def test_oversized_field_rejected(client: AsyncClient) -> None:
    r = await client.post("/v1/tool-calls", json=_evt(agent="a" * 500))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_demo_endpoints_off_unless_demo_mode(client: AsyncClient, monkeypatch) -> None:
    monkeypatch.setattr(settings, "demo_mode", False)
    assert (await client.post("/v1/demo/reset")).status_code == 404


@pytest.mark.asyncio
async def test_latency_metrics_measured(client: AsyncClient) -> None:
    await client.post("/v1/tool-calls", json=_evt())
    m = (await client.get("/v1/metrics/latency")).json()
    assert m["count"] >= 1 and m["total_p95_ms"] >= 0
