# Changelog

## 0.2.0 — review fixes

**Detector**
- Taint is tracked server-side (session, agent TTL, delegation chain); a caller can no longer clear it by omitting it.
- Agent-level rolling windows stop session-hopping from resetting volume/velocity counters.
- Identity binding via `registry/agents.yaml` (+ first-seen); mismatching claimed role raises `identity_mismatch`.
- Unknown role fails closed. Resource and destination normalization (scheme, userinfo, port).
- Learned per-role bigram baselines (EWMA), JS divergence and CUSUM with fading; baseline poisoning guarded.
- Ed25519 manifest signing; unsigned/tampered manifests are rejected. Optional embedding drift (off by default).

**Gateway**
- Decisions are enforced: isolated agents are denied, restricted agents are read-only with no egress.
- Step-up approvals are real (one approval releases one call). Audit log of privileged actions.
- API keys (`AIDDS_GATEWAY_API_KEY`, `AIDDS_ANALYST_API_KEY`); input length limits; `/v1/events/stream` route fixed;
  demo endpoints only with `--demo`; measured latency at `/v1/metrics/latency`; `python -m gateway`.

**Evaluation**: TTD measured from the first malicious event; held-out seeded generator with baseline methods
and ablations (`python -m eval.heldout`).

**Dashboard**: SSE works, API-key prompt, no hard-coded metrics, honest quality-gates tab, no mobile overflow.

**Hygiene**: `pydantic-settings`, `sqlalchemy[asyncio]`, `pynacl`, `numpy` added to requirements; dev/optional
requirements split; Dockerfile/Makefile/CI updated; tests isolated per test; 194 tests, 84% coverage.
