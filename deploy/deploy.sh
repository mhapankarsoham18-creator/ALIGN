#!/usr/bin/env bash
# AIDDS — Deploy to staging or production
# Usage: ./deploy/deploy.sh <environment> <version> [--canary <pct>] [--promote-after <duration>]

set -euo pipefail

ENV="${1:?Usage: deploy.sh <environment> <version>}"
VERSION="${2:?Usage: deploy.sh <environment> <version>}"
shift 2 || true

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
  exec "$PYTHON_CMD" -m deploy.ops deploy "$ENV" "$VERSION" "$@"
else
  echo "Deploying AIDDS version $VERSION to $ENV..."
  ./deploy/smoke.sh "$ENV"
fi
