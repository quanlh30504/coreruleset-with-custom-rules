#!/usr/bin/env bash
set -euo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "$ENV_DIR/logs" "$ENV_DIR/results"

truncate_log() {
  local name="$1"
  local host_path="$ENV_DIR/logs/$name"
  if : 2>/dev/null > "$host_path"; then
    return 0
  fi

  if docker compose -f "$ENV_DIR/docker-compose.yml" ps -q waf >/dev/null 2>&1; then
    docker compose -f "$ENV_DIR/docker-compose.yml" exec -T waf sh -c ": > /var/log/nginx/$name"
    return 0
  fi

  echo "ERR: cannot truncate $host_path; start the container or fix file permissions" >&2
  return 1
}

truncate_log access.log
truncate_log error.log
truncate_log modsec_audit.log

if [[ "${1:-}" == "--results" ]]; then
  find "$ENV_DIR/results" -type f -delete
fi

echo "reset logs in $ENV_DIR/logs"
