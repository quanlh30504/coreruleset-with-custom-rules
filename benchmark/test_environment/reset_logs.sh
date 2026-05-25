#!/usr/bin/env bash
# Usage:
#   ./reset_logs.sh
#   ./reset_logs.sh --dry-run
#   ./reset_logs.sh --method docker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=0
METHOD="auto"

ENVIRONMENTS=(
  "crs:rq1-waf-crs:$SCRIPT_DIR/crs/logs"
  "rr:rq1-waf-rr:$SCRIPT_DIR/rr/logs"
  "cgr:rq1-waf-cgr:$SCRIPT_DIR/cgr/logs"
)

LOG_FILES=(
  "access.log"
  "error.log"
  "modsec_audit.log"
)

usage() {
  cat <<'USAGE'
Usage:
  ./reset_logs.sh [--dry-run] [--method auto|host|docker] [--help]

Options:
  --dry-run              Show files that would be reset, but do not modify them.
  --method auto|host|docker
                         auto: truncate host file if writable, otherwise use docker.
                         host: only truncate host files. May require sudo.
                         docker: truncate logs from inside rq1-waf-* containers.
  --help                 Show this help message.

The script resets:
  crs/logs/{access.log,error.log,modsec_audit.log}
  rr/logs/{access.log,error.log,modsec_audit.log}
  cgr/logs/{access.log,error.log,modsec_audit.log}
USAGE
}

for arg in "$@"; do
  case "$arg" in
    --dry-run)
      DRY_RUN=1
      ;;
    --method=auto|--method=host|--method=docker)
      METHOD="${arg#--method=}"
      ;;
    --method)
      echo "Missing value for --method. Use auto, host, or docker." >&2
      usage >&2
      exit 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

container_running() {
  local container="$1"
  docker ps --format '{{.Names}}' 2>/dev/null | grep -Fxq "$container"
}

reset_container_logs() {
  local label="$1"
  local container="$2"
  local host_dir="$3"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    if container_running "$container"; then
      echo "[dry-run] would truncate logs via docker container: $container ($label)"
    else
      echo "[dry-run] container not running for docker reset: $container ($label)"
    fi

    for log_name in "${LOG_FILES[@]}"; do
      local file="$host_dir/$log_name"
      if [[ -e "$file" ]]; then
        local size
        size="$(du -h "$file" | awk '{print $1}')"
        echo "[dry-run] target: $file ($size)"
      else
        echo "[dry-run] target missing, would create after container writes: $file"
      fi
    done

    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    echo "docker command not found; cannot reset $label logs via container" >&2
    return 1
  fi

  if ! container_running "$container"; then
    echo "container not running: $container" >&2
    return 1
  fi

  docker exec "$container" sh -c '
    set -eu
    for log in access.log error.log modsec_audit.log; do
      mkdir -p /var/log/nginx
      : > "/var/log/nginx/$log"
    done
  '

  echo "reset via docker: $label ($container)"
}

reset_file() {
  local file="$1"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    if [[ -e "$file" ]]; then
      local size
      size="$(du -h "$file" | awk '{print $1}')"
      echo "[dry-run] would truncate: $file ($size)"
    else
      echo "[dry-run] would create empty log: $file"
    fi
    return 0
  fi

  if [[ -e "$file" && -w "$file" ]]; then
    truncate -s 0 "$file"
    echo "reset: $file"
    return 0
  fi

  if [[ ! -e "$file" && -w "$(dirname "$file")" ]]; then
    : > "$file"
    echo "created: $file"
    return 0
  fi

  echo "permission denied: $file" >&2
  return 1
}

host_logs_writable() {
  local host_dir="$1"

  for log_name in "${LOG_FILES[@]}"; do
    local file="$host_dir/$log_name"

    if [[ -e "$file" && ! -w "$file" ]]; then
      return 1
    fi

    if [[ ! -e "$file" && ! -w "$host_dir" ]]; then
      return 1
    fi
  done

  return 0
}

reset_host_logs() {
  local label="$1"
  local host_dir="$2"
  local failed=0

  for log_name in "${LOG_FILES[@]}"; do
    reset_file "$host_dir/$log_name" || failed=1
  done

  return "$failed"
}

main() {
  local failed=0

  echo "Resetting benchmark logs under: $SCRIPT_DIR"
  echo "Method: $METHOD"

  for env_spec in "${ENVIRONMENTS[@]}"; do
    IFS=":" read -r label container host_dir <<< "$env_spec"

    case "$METHOD" in
      host)
        reset_host_logs "$label" "$host_dir" || failed=1
        ;;
      docker)
        reset_container_logs "$label" "$container" "$host_dir" || failed=1
        ;;
      auto)
        if host_logs_writable "$host_dir"; then
          reset_host_logs "$label" "$host_dir" || failed=1
        else
          echo "host logs are not writable for $label; using docker container $container"
          reset_container_logs "$label" "$container" "$host_dir" || failed=1
        fi
        ;;
      *)
        echo "Invalid method: $METHOD" >&2
        exit 2
        ;;
    esac
  done

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "Dry run complete. No files were changed."
  elif [[ "$failed" -eq 0 ]]; then
    echo "All benchmark logs were reset."
  else
    echo "Some logs could not be reset." >&2
    exit 1
  fi
}

main
