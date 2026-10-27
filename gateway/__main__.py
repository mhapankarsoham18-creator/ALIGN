"""
Run the AIDDS gateway:

    python -m gateway                 # production-style: demo endpoints OFF
    python -m gateway --demo          # enable the dashboard's demo buttons and pre-listed agents
    python -m gateway --demo --port 9000

Works the same on Windows, macOS and Linux (no ``make`` needed).
"""

from __future__ import annotations

import argparse
import logging
import os


def main() -> None:
    parser = argparse.ArgumentParser(description="AIDDS gateway")
    parser.add_argument(
        "--host", default="127.0.0.1", help="bind address (default: localhost only)"
    )
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--demo", action="store_true", help="enable demo endpoints (never in production)"
    )
    parser.add_argument("--reload", action="store_true", help="auto-reload on code changes")
    args = parser.parse_args()

    if args.demo:
        os.environ["AIDDS_DEMO_MODE"] = "true"

    import uvicorn

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    uvicorn.run("gateway.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
