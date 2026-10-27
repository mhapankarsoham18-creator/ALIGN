"""
AIDDS Evaluation — Scenario runner.

Replays labelled scenario YAML files through the detector engine
and computes quality metrics: recall, false-positive rate,
time-to-detect (events before first correct alert).

Usage:
    python -m eval.run --scenarios eval/scenarios --out eval/report.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

import yaml

from detector.engine import score_event
from detector.registry import registered_role
from detector.signals import reset_tracker
from gateway.schemas import Action, DataClass, TaintEntry, ToolCallEvent


def _parse_scenario(path: pathlib.Path) -> dict[str, Any]:
    """Read a scenario YAML file and return its contents."""
    with open(path) as f:
        return yaml.safe_load(f)


def _build_event(
    raw_event: dict[str, Any],
    role: str,
    agent_id: str,
    session_id: str,
    manifest_version: int | None = None,
) -> ToolCallEvent:
    """Convert a raw scenario event dict into a ToolCallEvent."""
    taint_entries: list[TaintEntry] = []
    for t in raw_event.get("taint", []):
        taint_entries.append(
            TaintEntry(
                source=t["source"],
                ts=datetime.now(UTC),
                kind=t["kind"],
            )
        )

    mv = raw_event.get("manifest_version", manifest_version or 1)

    return ToolCallEvent(
        event_id=uuid.uuid4(),
        ts=datetime.now(UTC),
        agent_id=agent_id,
        role=role,
        session_id=session_id,
        tool=raw_event["tool"],
        action=Action(raw_event["action"]),
        resource=raw_event["resource"],
        data_class=DataClass(raw_event.get("data_class", "unknown")),
        sensitivity=raw_event.get("sensitivity", 0),
        destination=raw_event.get("destination"),
        bytes_out=raw_event.get("bytes_out", 0),
        taint=taint_entries,
        chain=raw_event.get("chain", []),
        manifest_version=mv,
        token_id=f"tok-eval-{session_id}",
    )


def _tier_order(tier: str) -> int:
    """Return an ordinal for tiers so we can compare severity."""
    order = {"observe": 0, "step_up": 1, "restrict": 2, "isolate": 3}
    return order.get(tier, 0)


def run_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    """
    Run a single scenario through the detector and return per-event results.

    Returns a dict with:
      - id, name, label, events, max_score, max_tier
      - detected: bool (True if any event triggered the expected tier or above)
      - detection_index: 0-based index of the first detection event, or -1
      - per_event: list of {tool, score, tier, decision, reasons}
    """
    # Reset session tracker for a clean slate per scenario
    reset_tracker()

    role = scenario["role"]
    agent_id = scenario["agent_id"]
    session_id = scenario["session_id"]
    label = scenario["label"]
    expected_tier = scenario.get("expected_tier", "observe")
    manifest_version = scenario.get("manifest_version")

    # Build manifest overrides for manifest_change scenarios
    manifest_overrides: dict[str, object] | None = None
    if "manifest_change" in scenario:
        manifest_overrides = scenario["manifest_change"]

    raw_events = scenario.get("events", [])
    per_event: list[dict[str, Any]] = []
    max_score = 0
    max_tier = "observe"
    detection_index = -1

    for i, raw_event in enumerate(raw_events):
        event = _build_event(raw_event, role, agent_id, session_id, manifest_version)
        decision = score_event(
            event,
            manifest_overrides=manifest_overrides,
            bound_role=registered_role(agent_id),
            learn=False,  # evaluation must never change the baselines it is measuring
        )

        event_result = {
            "index": i,
            "tool": raw_event["tool"],
            "data_class": raw_event.get("data_class", "unknown"),
            "score": decision.score,
            "tier": decision.tier.value,
            "decision": decision.decision.value,
            "reasons": [
                {"signal": r.signal, "points": r.points, "text": r.text} for r in decision.reasons
            ],
        }
        per_event.append(event_result)

        if decision.score > max_score:
            max_score = decision.score
        if _tier_order(decision.tier.value) > _tier_order(max_tier):
            max_tier = decision.tier.value

        # Track first detection — when we first reach the expected tier or above
        if detection_index == -1 and _tier_order(decision.tier.value) >= _tier_order(expected_tier):
            detection_index = i

    # For attack scenarios: detected = reached expected_tier or above
    # For benign scenarios: detected = stayed below threshold (no false alarm)
    if label == "attack":
        detected = detection_index >= 0
    else:
        # Benign: passes if max_score is below expected_max_score (default 39)
        max_allowed = scenario.get("expected_max_score", 39)
        detected = max_score <= max_allowed  # "detected" means "correctly classified"

    first_mal = int(scenario.get("first_malicious_index", 0)) if label == "attack" else None
    ttd = (
        max(0, detection_index - first_mal)
        if (label == "attack" and detection_index >= 0 and first_mal is not None)
        else None
    )
    return {
        "id": scenario["id"],
        "name": scenario["name"],
        "label": label,
        "expected_tier": expected_tier,
        "events": len(raw_events),
        "max_score": max_score,
        "max_tier": max_tier,
        "detected": detected,
        "detection_index": detection_index,
        "first_malicious_index": first_mal,
        "time_to_detect_events": ttd,  # events AFTER the first malicious action (0 = caught at it)
        "per_event": per_event,
    }


def compute_metrics(results: list[dict[str, Any]]) -> dict[str, float | int]:
    """
    Compute aggregate quality metrics from scenario results.

    Returns:
        recall: fraction of attack scenarios correctly detected
        false_positive_rate: fraction of benign scenarios that false-alarmed
        avg_time_to_detect_events: mean events from first malicious action to detection (attacks)
    """
    attack_results = [r for r in results if r["label"] == "attack"]
    benign_results = [r for r in results if r["label"] == "benign"]

    # Recall
    attacks_detected = sum(1 for r in attack_results if r["detected"])
    recall = attacks_detected / len(attack_results) if attack_results else 1.0

    # False positive rate
    benign_false_alarms = sum(1 for r in benign_results if not r["detected"])
    fpr = benign_false_alarms / len(benign_results) if benign_results else 0.0

    # Average time to detect (for correctly detected attacks)
    detected_attacks = [r for r in attack_results if r["detected"]]
    if detected_attacks:
        # detection_index is 0-based; we want "events after first malicious action"
        # For most scenarios, the first event is benign warmup, so index 1+ is detection
        avg_ttd = sum(r["time_to_detect_events"] or 0 for r in detected_attacks) / len(
            detected_attacks
        )
    else:
        avg_ttd = float("inf")

    return {
        "recall": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
        "avg_time_to_detect_events": round(avg_ttd, 2),
        "attacks_total": len(attack_results),
        "attacks_detected": attacks_detected,
        "benign_total": len(benign_results),
        "benign_correct": sum(1 for r in benign_results if r["detected"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="AIDDS Evaluation Runner")
    parser.add_argument(
        "--scenarios",
        type=str,
        default="eval/scenarios",
        help="Path to the directory of labelled scenario YAML files",
    )
    parser.add_argument(
        "--out",
        type=str,
        default="eval/report.json",
        help="Output path for the evaluation report JSON",
    )
    args = parser.parse_args()

    scenarios_dir = pathlib.Path(args.scenarios)
    if not scenarios_dir.exists():
        print(f"ERROR: scenarios directory not found: {scenarios_dir}", file=sys.stderr)
        sys.exit(1)

    scenario_files = sorted(scenarios_dir.glob("*.yaml"))
    print(f"Found {len(scenario_files)} scenario(s) in {scenarios_dir}")

    results: list[dict[str, Any]] = []

    for sf in scenario_files:
        scenario = _parse_scenario(sf)
        print(f"\n{'-' * 60}")
        print(f"  Running: {scenario['id']} - {scenario['name']}")
        print(
            f"  Label: {scenario['label']} | Expected: {scenario.get('expected_tier', 'observe')}"
        )

        result = run_scenario(scenario)
        results.append(result)

        # Print per-event results
        for ev in result["per_event"]:
            tier = ev["tier"]
            marker = {
                "isolate": "[!!]",
                "restrict": "[! ]",
                "step_up": "[? ]",
                "observe": "[ok]",
            }.get(tier, "[  ]")
            top_reason = ev["reasons"][0]["text"] if ev["reasons"] else "-"
            print(
                f"    [{ev['index']}] {marker} score={ev['score']:>3} "
                f"tier={tier:<10} {ev['tool']:<25} {top_reason}"
            )

        status = "PASS" if result["detected"] else "FAIL"
        print(
            f"  Result: {status} (max_score={result['max_score']}, max_tier={result['max_tier']})"
        )

    # Compute aggregate metrics
    metrics = compute_metrics(results)

    print(f"\n{'=' * 60}")
    print("  EVALUATION RESULTS")
    print(f"{'=' * 60}")
    print(
        f"  Recall:              {metrics['recall']:.4f}  "
        f"({metrics['attacks_detected']}/{metrics['attacks_total']} attacks)"
    )
    print(
        f"  False positive rate: {metrics['false_positive_rate']:.4f}  "
        f"({metrics['benign_total'] - metrics['benign_correct']}/{metrics['benign_total']} benign)"
    )
    print(f"  Avg time-to-detect:  {metrics['avg_time_to_detect_events']:.2f} events")
    print(f"{'=' * 60}\n")

    # Build report
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "scenarios_dir": str(scenarios_dir),
        "total_scenarios": len(results),
        "attack_scenarios": metrics["attacks_total"],
        "benign_scenarios": metrics["benign_total"],
        "results": {
            "recall": metrics["recall"],
            "false_positive_rate": metrics["false_positive_rate"],
            "avg_time_to_detect_events": metrics["avg_time_to_detect_events"],
        },
        "per_scenario": results,
    }

    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"Report written to {out_path}")


if __name__ == "__main__":
    main()
