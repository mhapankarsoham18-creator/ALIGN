#!/usr/bin/env bash
# AIDDS — Rollback a failed deployment
# Usage: ./deploy/rollback.sh <environment>

set -euo pipefail

ENV="${1:?Usage: rollback.sh <environment>}"
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
  exec "$PYTHON_CMD" -m deploy.ops rollback "$ENV" "$@"
else
  echo "Rolling back deployment on $ENV..."
  ./deploy/smoke.sh "$ENV"
fi
