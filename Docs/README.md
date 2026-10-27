# AIDDS - Identity Drift Detection for Autonomous AI Agents

AIDDS watches what AI agents *do*, not just whether their credentials are valid. It compares each
agent's live behaviour with its declared role and the learned behaviour of that role, scores the
risk, explains every alert, and restricts only the affected agent.

## How it works (30 seconds)

1. A **gateway** sits between agents and their tools, and logs every call as an event.
2. Each role has a signed **manifest** (allowed tools, data classes, destinations).
3. A **detector** scores each event: manifest rules, taint / kill-chain, sequence rarity,
   distribution drift (JS divergence, CUSUM), semantic drift.
4. A **risk engine** returns a 0-100 score with the top reasons.
5. A **response controller** applies: log (0-39), approve (40-69), restrict (70-89), isolate (90+).

## Quickstart

Requirements: Python 3.12, Docker (optional), Postgres 16 (integration tests only).

```bash
make install        # install dependencies
make run            # start the gateway on http://localhost:8000
make demo           # run the Procurement-agent injection scenario
make eval           # replay all labelled scenarios and check quality gates
make test           # unit + integration tests
make docker         # build the container image
```

Health check: `GET http://localhost:8000/healthz`

## Repository layout

```
gateway/       FastAPI gateway: interception, decisions, API
detector/      rules, taint tracking, baselines, scoring, explanations
manifests/     signed role manifests (YAML) and honeypot definitions
simulator/     simulated agents and attack scenarios
eval/          labelled scenarios, runner, quality gate
dashboard/     live dashboard (React)
docs/          design, plan, specs, threat model, evaluation, demo, ADRs
deploy/        deploy.sh, smoke.sh, rollback.sh
tests/         unit/ and integration/
.github/       CI and release workflows
```

## The demo in one line

A Procurement agent reads a supplier PDF with a hidden instruction, then tries to read HR salary
data and send it to an unknown server. Its token stays valid. AIDDS flags the kill chain, shows
the score climbing with reasons, restricts that agent, and a second legitimate agent keeps working.

## Quality gates (enforced in CI)

| Metric | Gate |
|---|---|
| Recall on attack scenarios | at least 0.90 |
| False-positive rate on benign scenarios | at most 0.05 |
| Time to detect | within 3 events of the first malicious action |
| Unit test coverage | at least 80% |

## Documentation

See `docs/`:
Architecture and Design, Phase-Wise Plan, Testing/CI-CD/Operations, Event Schema and API Spec,
Role Manifest Spec, Threat Model and Scenarios, Evaluation Plan, Demo Script, Pitch One-Pager,
Architecture Decision Records, Privacy and Compliance.

## Status

Prototype. Production-path items (Kafka pipeline, framework SDKs, SIEM/IAM connectors) are on the
roadmap in `docs/02_Phase_Wise_Plan.pdf`.
