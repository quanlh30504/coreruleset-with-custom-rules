#!/usr/bin/env bash
set -euo pipefail

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GTW_ROOT="${GTW_ROOT:-/home/quan3054/gotestwaf}"
GOTESTWAF_BIN="${GOTESTWAF_BIN:-$GTW_ROOT/gotestwaf}"
TESTCASES_PATH="${TESTCASES_PATH:-$GTW_ROOT/testcases/tunning-dataset}"
WAF_URL="${WAF_URL:-http://localhost:8086}"
REPORT_PATH="${REPORT_PATH:-$ENV_DIR/results}"
REPORT_NAME="${REPORT_NAME:-tunning-dataset}"
WORKERS="${WORKERS:-16}"
SEND_DELAY="${SEND_DELAY:-0}"
RANDOM_DELAY="${RANDOM_DELAY:-1}"
EXTRA_ARGS=()

if [[ -n "${TEST_SET:-}" ]]; then
  EXTRA_ARGS+=(--testSet "$TEST_SET")
fi

if [[ -n "${TEST_CASE:-}" ]]; then
  EXTRA_ARGS+=(--testCase "$TEST_CASE")
fi

mkdir -p "$REPORT_PATH"

if [[ ! -x "$GOTESTWAF_BIN" ]]; then
  echo "[build] $GOTESTWAF_BIN not found; building GoTestWAF"
  make -C "$GTW_ROOT" gotestwaf_bin
fi

if [[ ! -d "$TESTCASES_PATH" ]]; then
  echo "ERR: testcases path not found: $TESTCASES_PATH" >&2
  echo "Run: python3 $ENV_DIR/scripts/ingest_tunning_testcases.py" >&2
  exit 1
fi

if ! curl -fsS "$WAF_URL" >/dev/null; then
  echo "ERR: WAF is not reachable at $WAF_URL" >&2
  echo "Run: cd $ENV_DIR && docker compose up -d" >&2
  exit 1
fi

LOG_FILE="$REPORT_PATH/${REPORT_NAME}.gotestwaf.log"
echo "[run] GoTestWAF -> $WAF_URL"
echo "[run] testcases: $TESTCASES_PATH"
echo "[run] report: $REPORT_PATH/$REPORT_NAME"

"$GOTESTWAF_BIN" \
  --configPath "$GTW_ROOT/config.yaml" \
  --url "$WAF_URL" \
  --testCasesPath "$TESTCASES_PATH" \
  --reportPath "$REPORT_PATH" \
  --reportName "$REPORT_NAME" \
  --reportFormat html,json \
  --workers "$WORKERS" \
  --sendDelay "$SEND_DELAY" \
  --randomDelay "$RANDOM_DELAY" \
  --httpClient gohttp \
  --blockStatusCodes 403 \
  --passStatusCodes 200,404 \
  --addDebugHeader \
  --includePayloads \
  --skipWAFIdentification \
  --skipWAFBlockCheck \
  --noEmailReport \
  "${EXTRA_ARGS[@]}" 2>&1 | tee "$LOG_FILE"

echo "[done] detail CSV: $REPORT_PATH/${REPORT_NAME}_detail.csv"
echo "[done] console log: $LOG_FILE"
