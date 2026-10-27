"""Signing CLI, baseline CLI and the remaining gateway endpoints."""

from __future__ import annotations

import shutil
import sys
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from detector import baseline, signing
from gateway.database import close_db, init_db
from gateway.main import app


def test_signing_cli_init_sign_verify(tmp_path, monkeypatch, capsys) -> None:
    mdir = tmp_path / "manifests"
    shutil.copytree("manifests", mdir)
    keys = tmp_path / "keys"
    monkeypatch.setattr(
        sys,
        "argv",
        ["x", "init", "--manifests", str(mdir), "--keys-dir", str(keys), "--key-id", "k1"],
    )
    signing.main()
    assert (keys / "k1.key").exists()
    trusted = str(mdir / "trusted_keys.json")
    monkeypatch.setattr(
        sys, "argv", ["x", "verify", "--manifests", str(mdir), "--trusted", trusted]
    )
    with pytest.raises(SystemExit) as e:
        signing.main()
    assert e.value.code == 0
    # tamper -> verify fails
    p = mdir / "support-agent.yaml"
    p.write_text(p.read_text().replace("version: 1", "version: 9", 1))
    with pytest.raises(SystemExit) as e2:
        signing.main()
    assert e2.value.code == 1
    # re-sign with the key file -> verify passes again
    monkeypatch.setattr(
        sys, "argv", ["x", "sign", str(p), "--key-id", "k1", "--key-file", str(keys / "k1.key")]
    )
    signing.main()
    monkeypatch.setattr(
        sys, "argv", ["x", "verify", "--manifests", str(mdir), "--trusted", trusted]
    )
    with pytest.raises(SystemExit) as e3:
        signing.main()
    assert e3.value.code == 0
    assert "OK" in capsys.readouterr().out


def test_baseline_cli_train(tmp_path, monkeypatch) -> None:
    out = tmp_path / "b"
    monkeypatch.setattr(
        sys,
        "argv",
        ["x", "train", "--manifests", "manifests", "--out", str(out), "--sessions", "20"],
    )
    baseline.main()
    assert len(list(out.glob("*.json"))) == 3


@pytest_asyncio.fixture(autouse=True)
async def fresh_db() -> AsyncGenerator[None, None]:
    await init_db()
    yield
    await close_db()


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        yield ac


def _evt(**kw):
    base = {
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(UTC).isoformat(),
        "agent_id": "procurement-bot-04",
        "role": "procurement-agent",
        "session_id": "s",
        "tool": "hr_export_db",
        "action": "read",
        "resource": "hr/x.csv",
        "data_class": "hr",
        "sensitivity": 3,
        "destination": None,
        "bytes_out": 0,
        "taint": [],
        "chain": [],
        "manifest_version": 3,
        "token_id": "t",
    }
    base.update(kw)
    return base


@pytest.mark.asyncio
async def test_alert_flow_and_listings(client: AsyncClient) -> None:
    d = (
        await client.post("/v1/tool-calls", json=_evt(resource="hr/salaries_2026_FULL.xlsx"))
    ).json()
    aid = d["alert_id"]
    assert aid
    assert (await client.get(f"/v1/alerts/{aid}")).json()["alert_id"] == aid
    assert (await client.get("/v1/alerts?status=open")).status_code == 200
    r = await client.post(f"/v1/alerts/{aid}/feedback", json={"feedback": "false_alarm"})
    assert r.json()["feedback"] == "false_alarm"
    assert (
        await client.post(f"/v1/alerts/{aid}/feedback", json={"feedback": "bogus"})
    ).status_code == 422
    agents = (await client.get("/v1/agents")).json()
    assert any(a["agent_id"] == "procurement-bot-04" and a["status"] == "isolated" for a in agents)
    risk = (await client.get("/v1/agents/procurement-bot-04/risk")).json()
    assert risk["status"] == "isolated" and "all_calls_denied" in risk["restrictions"]
    ev = (await client.get("/v1/events?limit=5")).json()
    eid = ev["events"][0]["event_id"]
    assert (await client.get(f"/v1/events/{eid}")).json()["event_id"] == eid
    assert (await client.get("/v1/events/nope")).status_code == 404
    rp = (await client.post("/v1/events/replay?agent_id=procurement-bot-04")).json()
    assert rp["replayed"] >= 1
    m = (await client.get("/v1/manifests")).json()
    assert {x["role"] for x in m["loaded"]} >= {"procurement-agent"}
    assert (await client.get("/v1/eval/metrics")).status_code == 200
    assert any(a["action"] == "alert.feedback" for a in (await client.get("/v1/audit")).json())


@pytest.mark.asyncio
async def test_restricted_agent_is_read_only(client: AsyncClient) -> None:
    # tainted read -> large egress through an allowed tool pushes the agent into restrict territory
    t = [{"source": "inbox/a.pdf", "ts": datetime.now(UTC).isoformat(), "kind": "document"}]
    await client.post(
        "/v1/tool-calls",
        json=_evt(
            tool="read_catalog", data_class="pricing", sensitivity=1, resource="c/1", taint=t
        ),
    )
    r = (
        await client.post(
            "/v1/tool-calls",
            json=_evt(
                tool="http_post",
                action="write",
                data_class="pricing",
                sensitivity=2,
                resource="out",
                destination="evil.example.net",
                bytes_out=300_000,
                taint=t,
            ),
        )
    ).json()
    assert r["tier"] in {"restrict", "isolate", "step_up"}


@pytest.mark.asyncio
async def test_demo_simulate_and_reset(client: AsyncClient) -> None:
    r = await client.post(
        "/v1/demo/simulate", json={"scenario": "procurement_injection", "delay_ms": 0}
    )
    assert r.status_code == 200 and r.json()["count"] >= 3
    assert (
        await client.post("/v1/demo/simulate", json={"scenario": "nope", "delay_ms": 0})
    ).status_code == 400
    assert (await client.post("/v1/demo/reset")).status_code == 200
