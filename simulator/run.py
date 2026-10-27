"""
AIDDS Simulator — Scenario runner.

Sends simulated agent events through the gateway via httpx.

Usage:
    python -m simulator.run --scenario procurement_injection
    python -m simulator.run --scenario normal_procurement
    python -m simulator.run --list
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import sys
import time

import httpx

from simulator.agents import SCENARIOS, get_scenario_events


async def run_scenario(
    scenario_name: str,
    gateway_url: str,
    delay_ms: int = 100,
) -> None:
    """Send a scenario's events through the gateway one by one."""
    # Reconfigure stdout to UTF-8 if possible
    if hasattr(sys.stdout, "reconfigure"):
        with contextlib.suppress(Exception):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    events = get_scenario_events(scenario_name)

    print(f"\n{'=' * 60}")
    print(f"  AIDDS Simulator -- {scenario_name}")
    print(f"  Gateway: {gateway_url}")
    print(f"  Events:  {len(events)}")
    print(f"{'=' * 60}\n")

    async with httpx.AsyncClient(base_url=gateway_url, timeout=10.0) as client:
        # Health check first
        try:
            r = await client.get("/healthz")
            r.raise_for_status()
            print(f"  [+] Gateway healthy: {r.json()}\n")
        except httpx.HTTPError as e:
            print(f"  [-] Gateway not reachable: {e}")
            print("    Start the gateway with: make run")
            sys.exit(1)

        for i, event in enumerate(events, 1):
            payload = event.model_dump(mode="json")
            # Convert UUID to string and datetime to ISO format for JSON
            payload["event_id"] = str(payload["event_id"])

            start = time.perf_counter_ns()
            r = await client.post("/v1/tool-calls", json=payload)
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000

            if r.status_code == 200:
                decision = r.json()
                score = decision.get("score", "?")
                tier = decision.get("tier", "?")
                dec = decision.get("decision", "?")

                # ASCII/Unicode friendly marker
                if tier == "isolate":
                    marker = "[!! ISOLATE ]"
                elif tier == "restrict":
                    marker = "[!  RESTRICT]"
                elif tier == "step_up":
                    marker = "[?  STEP-UP ]"
                else:
                    marker = "[   OBSERVE ]"

                print(
                    f"  [{i}/{len(events)}] {marker} "
                    f"tool={event.tool:<25s} "
                    f"data_class={event.data_class.value:<18s} "
                    f"score={score:>3}  tier={tier:<10s} "
                    f"decision={dec:<10s} "
                    f"({elapsed_ms:.1f}ms)"
                )
            else:
                print(f"  [{i}/{len(events)}] [x] HTTP {r.status_code}: {r.text}")

            # Small delay between events (simulates real agent timing)
            if delay_ms > 0 and i < len(events):
                await asyncio.sleep(delay_ms / 1000)

    print(f"\n{'=' * 60}")
    print(f"  Scenario '{scenario_name}' complete -- {len(events)} events sent")
    print(f"{'=' * 60}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="AIDDS Agent Simulator")
    parser.add_argument(
        "--scenario",
        type=str,
        default="procurement_injection",
        help="Scenario to run",
    )
    parser.add_argument(
        "--gateway-url",
        type=str,
        default="http://localhost:8000",
        help="Gateway base URL",
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=100,
        help="Delay between events in ms (default: 100)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available scenarios and exit",
    )
    args = parser.parse_args()

    if args.list:
        print("\nAvailable scenarios:")
        for name in sorted(SCENARIOS.keys()):
            events = get_scenario_events(name)
            print(f"  {name:<40s} ({len(events)} events)")
        print()
        return

    asyncio.run(run_scenario(args.scenario, args.gateway_url, args.delay))


if __name__ == "__main__":
    main()
