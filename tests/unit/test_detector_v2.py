"""
Tests for the second-generation detector features:

  * server-side taint (sticky per session / agent, propagated along delegation chains)
  * agent-level rolling windows (session-hopping does not reset volume or violations)
  * identity binding and fail-closed unknown roles
  * learned per-role baselines (Markov rarity, JS divergence, EWMA) and poisoning resistance
  * CUSUM slow-drift accumulation and fading
  * manifest signing, agent registry, optional semantic signal
"""

from __future__ import annotations

import json
import pathlib
import uuid
from datetime import UTC, datetime

import pytest

from detector.baseline import (
    MIN_OBS,
    START,
    BaselineStore,
    RoleBaseline,
    js_divergence,
    train_from_manifests,
)
from detector.engine import score_event
from detector.manifest_loader import _load_manifests_from_dir, get_manifest, reload_manifests
from detector.registry import load_registry
from detector.schemas import RoleManifest
from detector.semantic import SemanticDrift, check_semantic_drift
from detector.signals import (
    CUSUM_H,
    SessionTracker,
    check_cumulative_drift,
    reset_tracker,
    update_cusum,
)
from detector.signing import (
    canonical_bytes,
    generate_keypair,
    load_trusted_keys,
    sign_manifest,
    verify_manifest,
)
from gateway.schemas import Action, DataClass, Tier, ToolCallEvent

T0 = 1_000_000.0


def ev(
    *,
    agent: str = "procurement-bot-04",
    role: str = "procurement-agent",
    session: str = "s1",
    tool: str = "read_catalog",
    resource: str = "catalog/a.csv",
    dc: DataClass = DataClass.PRICING,
    sens: int = 1,
    dest: str | None = None,
    bytes_out: int = 0,
    taint: bool = False,
    chain: list[str] | None = None,
    action: Action = Action.READ,
) -> ToolCallEvent:
    from gateway.schemas import TaintEntry

    return ToolCallEvent(
        event_id=uuid.uuid4(),
        agent_id=agent,
        role=role,
        session_id=session,
        tool=tool,
        action=action,
        resource=resource,
        data_class=dc,
        sensitivity=sens,
        destination=dest,
        bytes_out=bytes_out,
        taint=[TaintEntry(source="evil.pdf", ts=datetime.now(UTC), kind="document")]
        if taint
        else [],
        chain=chain or [],
        manifest_version=3,
        token_id="tok-test",
    )


@pytest.fixture(autouse=True)
def _clean() -> None:
    reset_tracker()
    reload_manifests()


def run(events: list[ToolCallEvent], tracker: SessionTracker | None = None, **kw):  # type: ignore[no-untyped-def]
    tracker = tracker or SessionTracker()
    store = kw.pop("baselines", BaselineStore())
    out = []
    t = T0
    for e in events:
        out.append(score_event(e, tracker=tracker, baselines=store, now=t, learn=False, **kw))
        t += 1
    return out


# ---------------------------------------------------------------------------
# Server-side taint
# ---------------------------------------------------------------------------


class TestServerSideTaint:
    def test_taint_persists_when_later_events_omit_the_field(self) -> None:
        """The client cannot shed taint by simply not repeating it."""
        decisions = run(
            [
                ev(
                    tool="supplier_price_api",
                    resource="evil.pdf",
                    dc=DataClass.SUPPLIER,
                    taint=True,
                ),
                ev(tool="hr_export_db", resource="hr/salaries.xlsx", dc=DataClass.HR, sens=3),
                ev(
                    tool="http_post",
                    action=Action.SEND,
                    resource="x",
                    dc=DataClass.HR,
                    sens=3,
                    dest="evil.example",
                    bytes_out=48_000,
                ),
            ]
        )
        assert decisions[0].tier == Tier.OBSERVE
        assert any(r.signal == "taint_flow" for r in decisions[1].reasons)
        assert decisions[2].tier == Tier.ISOLATE
        assert any(r.signal == "kill_chain" for r in decisions[2].reasons)

    def test_new_session_id_does_not_shed_recent_taint(self) -> None:
        decisions = run(
            [
                ev(session="a", resource="evil.pdf", taint=True, dc=DataClass.SUPPLIER),
                ev(session="b", tool="hr_export_db", resource="hr/x", dc=DataClass.HR, sens=3),
            ]
        )
        assert any(r.signal == "taint_flow" for r in decisions[1].reasons)

    def test_taint_expires_after_ttl(self) -> None:
        tracker = SessionTracker()
        score_event(ev(session="a", taint=True), tracker=tracker, now=T0, learn=False)
        later = T0 + 3600  # an hour later, in a brand-new session
        d = score_event(
            ev(session="b", tool="hr_export_db", resource="hr/x", dc=DataClass.HR, sens=3),
            tracker=tracker,
            now=later,
            learn=False,
        )
        assert not any(r.signal == "taint_flow" for r in d.reasons)

    def test_tainted_but_in_role_work_is_not_penalised(self) -> None:
        decisions = run(
            [
                ev(resource="evil.pdf", taint=True),
                ev(
                    tool="supplier_price_api",
                    dc=DataClass.SUPPLIER,
                    dest="api.approved-supplier.com",
                ),
            ]
        )
        assert all(d.tier == Tier.OBSERVE for d in decisions)

    def test_taint_propagates_along_delegation_chain(self) -> None:
        tracker = SessionTracker()
        score_event(
            ev(agent="agent-a", session="a", resource="evil.pdf", taint=True),
            tracker=tracker,
            now=T0,
            learn=False,
        )
        d = score_event(
            ev(
                agent="agent-b",
                session="b",
                role="procurement-agent",
                tool="hr_export_db",
                resource="hr/x",
                dc=DataClass.HR,
                sens=3,
                chain=["agent-a", "agent-b"],
            ),
            tracker=tracker,
            now=T0 + 5,
            learn=False,
        )
        assert any(r.signal == "taint_flow" for r in d.reasons)


# ---------------------------------------------------------------------------
# Agent-level windows
# ---------------------------------------------------------------------------


class TestSessionHopping:
    def test_cumulative_exfil_across_sessions_is_still_counted(self) -> None:
        """Opening a fresh session id for every call must not reset the hourly byte budget."""
        tracker = SessionTracker()
        last = None
        t = T0
        for i in range(30):
            last = score_event(
                ev(
                    session=f"hop-{i}",
                    tool="supplier_price_api",
                    dc=DataClass.SUPPLIER,
                    dest="api.approved-supplier.com",
                    bytes_out=200_000,
                ),
                tracker=tracker,
                now=t,
                learn=False,
            )
            t += 20
        assert last is not None  # 30 x 200 KB = 6 MB > the 5 MB hourly limit, across 30 sessions
        velocity = [r for r in last.reasons if r.signal == "velocity"]
        assert velocity and "exceeds hourly limit" in velocity[0].text
        assert last.score >= 40

    def test_byte_window_expires(self) -> None:
        tracker = SessionTracker()
        for i in range(10):
            score_event(
                ev(
                    session=f"x{i}",
                    tool="supplier_price_api",
                    dc=DataClass.SUPPLIER,
                    dest="api.approved-supplier.com",
                    bytes_out=200_000,
                ),
                tracker=tracker,
                now=T0 + i,
                learn=False,
            )
        d = score_event(
            ev(
                session="fresh",
                tool="supplier_price_api",
                dc=DataClass.SUPPLIER,
                dest="api.approved-supplier.com",
                bytes_out=100,
            ),
            tracker=tracker,
            now=T0 + 3 * 3600,
            learn=False,
        )
        assert d.tier == Tier.OBSERVE

    def test_tracker_is_lru_bounded(self) -> None:
        tracker = SessionTracker(max_sessions=50, max_agents=50)
        for i in range(500):
            score_event(
                ev(agent=f"a{i}", session=f"s{i}"), tracker=tracker, now=T0 + i, learn=False
            )
        assert len(tracker._sessions) <= 50
        assert len(tracker._agents) <= 50


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class TestIdentity:
    def test_spoofed_role_is_scored_against_bound_role(self) -> None:
        spoof = ev(
            role="hr-assistant-agent",
            tool="hr_export_db",
            resource="hr/salaries.xlsx",
            dc=DataClass.HR,
            sens=3,
        )
        d = score_event(
            spoof, bound_role="procurement-agent", tracker=SessionTracker(), now=T0, learn=False
        )
        signals = {r.signal for r in d.reasons}
        assert "identity_mismatch" in signals
        assert "role_violation" in signals  # HR data is forbidden for the BOUND role
        assert d.tier != Tier.OBSERVE

    def test_matching_claim_has_no_mismatch(self) -> None:
        d = score_event(
            ev(), bound_role="procurement-agent", tracker=SessionTracker(), now=T0, learn=False
        )
        assert d.tier == Tier.OBSERVE

    def test_unknown_role_fails_closed(self) -> None:
        d = score_event(
            ev(
                role="totally-made-up-role",
                tool="hr_export_db",
                resource="hr/salaries.xlsx",
                dc=DataClass.HR,
                sens=3,
                dest="evil.example",
                bytes_out=48_000,
            ),
            tracker=SessionTracker(),
            now=T0,
            learn=False,
        )
        assert d.tier in (Tier.STEP_UP, Tier.RESTRICT, Tier.ISOLATE)
        assert d.score >= 40

    def test_destination_with_port_matches_allowlist(self) -> None:
        d = run(
            [
                ev(
                    tool="supplier_price_api",
                    dc=DataClass.SUPPLIER,
                    dest="api.approved-supplier.com:443",
                    bytes_out=200,
                )
            ]
        )[0]
        assert d.tier == Tier.OBSERVE


# ---------------------------------------------------------------------------
# Learned baselines
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def trained() -> BaselineStore:
    return train_from_manifests("manifests", sessions=200, seed=3)


class TestBaselines:
    def test_seeded_baseline_has_enough_observations(self, trained: BaselineStore) -> None:
        b = trained.get("procurement-agent")
        assert b is not None and b.n_obs >= MIN_OBS

    def test_in_role_transition_is_not_rare(self, trained: BaselineStore) -> None:
        b = trained.get("procurement-agent")
        assert b is not None
        assert b.prob("read_catalog", "supplier_price_api") > 0.05

    def test_unseen_tool_is_rare(self, trained: BaselineStore) -> None:
        b = trained.get("procurement-agent")
        assert b is not None
        assert b.prob("read_catalog", "hr_export_db") < 0.01

    def test_rarity_signal_fires_for_unseen_tool(self, trained: BaselineStore) -> None:
        d = score_event(
            ev(tool="hr_export_db", resource="hr/a", dc=DataClass.HR, sens=1),
            tracker=SessionTracker(),
            baselines=trained,
            now=T0,
            learn=False,
        )
        assert any(r.signal == "sequence_rarity" for r in d.reasons)

    def test_cold_start_has_no_statistical_signal(self) -> None:
        empty = BaselineStore()
        d = score_event(
            ev(tool="hr_export_db", resource="hr/a", dc=DataClass.HR),
            tracker=SessionTracker(),
            baselines=empty,
            now=T0,
            learn=False,
        )
        assert not any(r.signal in ("sequence_rarity", "distribution_drift") for r in d.reasons)
        # ...but the manifest rules still catch it
        assert any(r.signal == "role_violation" for r in d.reasons)

    def test_js_divergence_bounds(self) -> None:
        p = {"a": 1.0}
        assert js_divergence(p, p) == pytest.approx(0.0)
        assert js_divergence({"a": 1.0}, {"b": 1.0}) == pytest.approx(1.0)
        assert 0 < js_divergence({"a": 0.5, "b": 0.5}, {"a": 0.9, "b": 0.1}) < 1

    def test_distribution_drift_fires_when_tool_mix_changes(self, trained: BaselineStore) -> None:
        tracker = SessionTracker()
        last = None
        for i in range(15):  # same tool again and again, plus allowed-but-skewed
            last = score_event(
                ev(tool="hr_export_db", resource=f"hr/{i}", dc=DataClass.HR),
                tracker=tracker,
                baselines=trained,
                now=T0 + i,
                learn=False,
            )
        assert last is not None
        assert any(r.signal == "distribution_drift" for r in last.reasons)

    def test_ewma_forgets_old_behaviour(self) -> None:
        b = RoleBaseline("r", decay=0.99)
        for _ in range(500):
            b.update(START, "old")
        p_before = b.prob(START, "new")
        for _ in range(500):
            b.update(START, "new")
        assert b.prob(START, "new") > p_before
        assert b.prob(START, "new") > b.prob(START, "old")

    def test_roundtrip_serialisation(self, trained: BaselineStore, tmp_path: pathlib.Path) -> None:
        trained.save_dir(tmp_path)
        again = BaselineStore()
        assert again.load_dir(tmp_path) == len(trained.roles())
        a, b = trained.get("support-agent"), again.get("support-agent")
        assert a is not None and b is not None
        assert b.prob("ticket_system", "knowledge_base") == pytest.approx(
            a.prob("ticket_system", "knowledge_base"), rel=1e-3
        )

    def test_attacker_cannot_poison_the_baseline(self, trained: BaselineStore) -> None:
        """Repeating an out-of-role tool must never teach the model it is normal."""
        store = BaselineStore()
        store.put(RoleBaseline.from_dict(trained.get("procurement-agent").to_dict()))  # type: ignore[union-attr]
        tracker = SessionTracker()
        for i in range(200):
            score_event(
                ev(tool="hr_export_db", resource=f"hr/{i}", dc=DataClass.HR),
                tracker=tracker,
                baselines=store,
                now=T0 + i,
                learn=True,
            )
        b = store.get("procurement-agent")
        assert b is not None
        assert b.prob("hr_export_db", "hr_export_db") < 0.05

    def test_tainted_traffic_does_not_train(self, trained: BaselineStore) -> None:
        store = BaselineStore()
        store.put(RoleBaseline.from_dict(trained.get("procurement-agent").to_dict()))  # type: ignore[union-attr]
        before = store.get("procurement-agent").n_obs  # type: ignore[union-attr]
        score_event(ev(taint=True), tracker=SessionTracker(), baselines=store, now=T0, learn=True)
        assert store.get("procurement-agent").n_obs == pytest.approx(before)  # type: ignore[union-attr]

    def test_clean_traffic_does_train(self, trained: BaselineStore) -> None:
        store = BaselineStore()
        store.put(RoleBaseline.from_dict(trained.get("procurement-agent").to_dict()))  # type: ignore[union-attr]
        n0 = store.get("procurement-agent").n_obs  # type: ignore[union-attr]
        score_event(ev(), tracker=SessionTracker(), baselines=store, now=T0, learn=True)
        assert store.get("procurement-agent").n_obs > n0 - 1e-6  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# CUSUM
# ---------------------------------------------------------------------------


class TestCusum:
    def test_repeated_small_anomalies_accumulate(self) -> None:
        tracker = SessionTracker()
        agent = tracker.agent("a")
        s = 0.0
        for i in range(6):
            s = update_cusum(agent, 0.35, T0 + i)
        assert s >= CUSUM_H
        reason = check_cumulative_drift(s)
        assert reason is not None and reason.points >= 10

    def test_normal_events_drain_the_accumulator(self) -> None:
        tracker = SessionTracker()
        agent = tracker.agent("a")
        for i in range(4):
            update_cusum(agent, 0.5, T0 + i)
        for i in range(20):
            s = update_cusum(agent, 0.0, T0 + 10 + i)
        assert s == 0.0
        assert check_cumulative_drift(s) is None

    def test_evidence_fades_over_days(self) -> None:
        tracker = SessionTracker()
        agent = tracker.agent("a")
        for i in range(4):
            update_cusum(agent, 0.6, T0 + i)
        before = agent.cusum
        s = update_cusum(agent, 0.0, T0 + 30 * 86400)
        assert s < before * 0.1

    def test_slow_drift_across_days_and_sessions_reaches_step_up(
        self, trained: BaselineStore
    ) -> None:
        """One mildly out-of-scope read per day, each in a new session, must add up."""
        tracker = SessionTracker()
        day = 86400.0
        tiers = []
        for d in range(8):
            for tool, dc in (
                ("read_catalog", DataClass.PRICING),
                ("read_catalog", DataClass.PRICING),
            ):
                score_event(
                    ev(session=f"d{d}-ok", tool=tool, dc=dc),
                    tracker=tracker,
                    baselines=trained,
                    now=T0 + d * day,
                    learn=False,
                )
            r = score_event(
                ev(
                    session=f"d{d}-drift",
                    tool="read_catalog",
                    resource=f"hr/org-{d}.json",
                    dc=DataClass.HR,
                    sens=1,
                ),
                tracker=tracker,
                baselines=trained,
                now=T0 + d * day + 60,
                learn=False,
            )
            tiers.append(r.tier)
        assert any(t != Tier.OBSERVE for t in tiers)


# ---------------------------------------------------------------------------
# Signing / registry / semantic
# ---------------------------------------------------------------------------


def _manifest() -> RoleManifest:
    m = get_manifest("procurement-agent")
    assert m is not None
    return m


class TestSigning:
    def test_shipped_manifests_verify(self) -> None:
        trusted = load_trusted_keys("manifests/trusted_keys.json")
        loaded = _load_manifests_from_dir(pathlib.Path("manifests"), trusted)
        assert set(loaded) == {"procurement-agent", "hr-assistant-agent", "support-agent"}

    def test_sign_and_verify_roundtrip(self) -> None:
        priv, pub = generate_keypair()
        m = _manifest().model_copy(deep=True)
        m.signature = sign_manifest(m, "k1", priv)
        assert verify_manifest(m, {"k1": pub}) == (True, "ok")

    def test_tampering_is_detected(self) -> None:
        priv, pub = generate_keypair()
        m = _manifest().model_copy(deep=True)
        m.signature = sign_manifest(m, "k1", priv)
        m.forbidden_data_classes = []  # attacker removes the HR restriction
        ok, reason = verify_manifest(m, {"k1": pub})
        assert not ok and "does not match" in reason

    def test_untrusted_key_rejected(self) -> None:
        priv, _ = generate_keypair()
        _, other_pub = generate_keypair()
        m = _manifest().model_copy(deep=True)
        m.signature = sign_manifest(m, "k1", priv)
        assert not verify_manifest(m, {"k1": other_pub})[0]
        assert not verify_manifest(m, {})[0]

    def test_placeholder_signature_rejected(self) -> None:
        m = _manifest().model_copy(deep=True)
        m.signature = "ed25519:placeholder_signature_procurement_v3"
        assert not verify_manifest(m, {"k": generate_keypair()[1]})[0]

    def test_canonical_bytes_ignore_signature(self) -> None:
        m = _manifest().model_copy(deep=True)
        a = canonical_bytes(m)
        m.signature = "anything"
        assert canonical_bytes(m) == a

    def test_unsigned_manifest_is_not_loaded(self, tmp_path: pathlib.Path) -> None:
        src = pathlib.Path("manifests/procurement-agent.yaml").read_text(encoding="utf-8")
        (tmp_path / "x.yaml").write_text(src.replace("ed25519:", "ed25519-bad:"), encoding="utf-8")
        loaded = _load_manifests_from_dir(
            tmp_path, load_trusted_keys("manifests/trusted_keys.json")
        )
        assert loaded == {}


class TestRegistry:
    def test_registry_file(self, tmp_path: pathlib.Path) -> None:
        f = tmp_path / "a.yaml"
        f.write_text("agents:\n  bot-1: procurement-agent\n", encoding="utf-8")
        assert load_registry(f) == {"bot-1": "procurement-agent"}
        assert load_registry(tmp_path / "missing.yaml") == {}

    def test_shipped_registry(self) -> None:
        reg = load_registry("registry/agents.yaml")
        assert reg["procurement-bot-04"] == "procurement-agent"


class TestSemantic:
    @staticmethod
    def _enc(texts):  # type: ignore[no-untyped-def]
        # toy encoder: bag of two "topics" so similarity is controllable
        def vec(t: str) -> list[float]:
            t = t.lower()
            return [
                float(t.count("price") + t.count("supplier") + t.count("catalog")),
                float(t.count("hr") + t.count("salary") + t.count("payroll")),
            ]

        return [vec(t) for t in texts]

    def test_on_topic_activity_scores_zero(self) -> None:
        d = SemanticDrift(encoder=self._enc)
        window = ["read supplier price catalog"] * 6
        assert check_semantic_drift(_manifest(), window, d) is None

    def test_off_topic_activity_scores(self) -> None:
        d = SemanticDrift(encoder=self._enc)
        window = ["read hr salary payroll"] * 6
        r = check_semantic_drift(_manifest(), window, d)
        assert r is not None and 1 <= r.points <= 10

    def test_short_window_ignored(self) -> None:
        d = SemanticDrift(encoder=self._enc)
        assert check_semantic_drift(_manifest(), ["read hr salary"], d) is None


def test_replay_style_scoring_leaves_live_tracker_untouched() -> None:
    from detector.signals import get_tracker

    live = get_tracker()
    before = len(live._sessions)
    score_event(ev(session="isolated-run"), tracker=SessionTracker(), now=T0, learn=False)
    assert len(get_tracker()._sessions) == before


def test_trusted_keys_file_is_valid_json() -> None:
    data = json.loads(pathlib.Path("manifests/trusted_keys.json").read_text(encoding="utf-8"))
    assert data["keys"]
