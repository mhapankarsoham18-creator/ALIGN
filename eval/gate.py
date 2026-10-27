"""
AIDDS Evaluation — Quality gate checker.

Reads the eval report and fails if quality metrics are below thresholds.

Usage:
    python -m eval.gate --report eval/report.json \
        --min-recall 0.90 --max-fpr 0.05 --max-ttd-events 3
"""

from __future__ import annotations

import argparse
import json
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="AIDDS Detection Quality Gate")
    parser.add_argument("--report", type=str, required=True, help="Path to eval report JSON")
    parser.add_argument("--min-recall", type=float, default=0.90)
    parser.add_argument("--max-fpr", type=float, default=0.05)
    parser.add_argument("--max-ttd-events", type=int, default=3)
    args = parser.parse_args()

    with open(args.report) as f:
        report = json.load(f)

    results = report.get("results", {})
    recall = results.get("recall", 0.0)
    fpr = results.get("false_positive_rate", 0.0)
    ttd = results.get("avg_time_to_detect_events", 0)

    passed = True

    if recall < args.min_recall:
        print(f"FAIL: recall {recall:.3f} < {args.min_recall:.3f}")
        passed = False
    else:
        print(f"PASS: recall {recall:.3f} >= {args.min_recall:.3f}")

    if fpr > args.max_fpr:
        print(f"FAIL: false_positive_rate {fpr:.3f} > {args.max_fpr:.3f}")
        passed = False
    else:
        print(f"PASS: false_positive_rate {fpr:.3f} <= {args.max_fpr:.3f}")

    if ttd > args.max_ttd_events:
        print(f"FAIL: avg_time_to_detect {ttd} > {args.max_ttd_events}")
        passed = False
    else:
        print(f"PASS: avg_time_to_detect {ttd} <= {args.max_ttd_events}")

    # Phase 0: stub report always has zeros, so gate passes trivially.
    # Real enforcement begins when the scoring pipeline is wired.
    note = report.get("note", "")
    if "stub" in note.lower():
        print("NOTE: stub report detected — gate passes trivially in Phase 0")

    if not passed:
        sys.exit(1)
    else:
        print("All quality gates PASSED.")


if __name__ == "__main__":
    main()
