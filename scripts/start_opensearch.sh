#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$PROJECT_ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not installed. Install Docker or use an OpenSearch endpoint via OPENSEARCH_URL."
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  echo "Starting OpenSearch container..."
  if docker compose up -d opensearch; then
    echo "OpenSearch container started."
    echo "Use 'docker compose ps' to check status."
    exit 0
  fi
else
  echo "Docker Compose is not available. Use 'docker compose' via Docker CLI."
  exit 1
fi
