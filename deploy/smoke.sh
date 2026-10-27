#!/usr/bin/env bash
# AIDDS — Smoke test for a deployed environment
# Usage: ./deploy/smoke.sh <environment> [--url <url>]

set -euo pipefail

ENV="${1:?Usage: smoke.sh <environment>}"
shift || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if command -v python3 &> /dev/null; then
  PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
  PYTHON_CMD="python"
else
  PYTHON_CMD=""
fi

if [ -n "$PYTHON_CMD" ]; then
  exec "$PYTHON_CMD" -m deploy.ops smoke "$ENV" "$@"
else
  BASE_URL="${AIDDS_GATEWAY_URL:-http://127.0.0.1:8000}"
  echo "Running bash smoke test against $BASE_URL..."
  curl -fsS "$BASE_URL/healthz" > /dev/null
  curl -fsS "$BASE_URL/dashboard" > /dev/null
  curl -fsS "$BASE_URL/v1/agents" > /dev/null
  echo "Smoke tests passed!"
fi
