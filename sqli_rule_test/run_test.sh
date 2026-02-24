#!/bin/bash
# SQLi Rule Test Script
# Tests the new generalized SQLi rules using GoTestWAF

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "============================================================"
echo "SQLi Rule Testing Environment"
echo "Rule: REQUEST-942-APPLICATION-CUSTOM-ATTACK-SQLI-GENERALIZED"
echo "Rule IDs: 300000-300014"
echo "============================================================"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up containers...${NC}"
    docker compose down --remove-orphans 2>/dev/null || true
}

# Trap to ensure cleanup on script exit
trap cleanup EXIT

# Step 1: Stop any existing containers
echo -e "${YELLOW}[1/7] Stopping any existing containers...${NC}"
docker compose down --remove-orphans 2>/dev/null || true

# Create necessary directories
mkdir -p logs reports

# Step 2: Start WAF and backend
echo -e "${YELLOW}[2/7] Starting WAF and backend containers...${NC}"
docker compose up -d waf backend

# Step 3: Wait for WAF to be healthy
echo -e "${YELLOW}[3/7] Waiting for WAF to be ready...${NC}"
MAX_WAIT=60
WAIT_COUNT=0
while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    if curl -s http://localhost:8081/ > /dev/null 2>&1; then
        echo -e "${GREEN}WAF is ready!${NC}"
        break
    fi
    sleep 2
    WAIT_COUNT=$((WAIT_COUNT + 2))
    echo "  Waiting... ($WAIT_COUNT/$MAX_WAIT seconds)"
done

if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
    echo -e "${RED}WAF failed to start within ${MAX_WAIT} seconds${NC}"
    echo "Check logs with: docker compose logs waf"
    exit 1
fi

# Step 4: Manual SQLi detection tests
echo ""
echo -e "${YELLOW}[4/7] Running manual SQLi detection tests...${NC}"
echo ""

PASS=0
FAIL=0

run_test() {
    local description="$1"
    local url="$2"
    local expected="$3"
    
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    if [ "$RESPONSE" = "$expected" ]; then
        echo -e "  ${GREEN}✓ PASS${NC} - $description (HTTP $RESPONSE)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗ FAIL${NC} - $description (HTTP $RESPONSE, expected $expected)"
        FAIL=$((FAIL + 1))
    fi
}

echo -e "${BLUE}--- Attack Detection Tests (should block = 403) ---${NC}"

# UNION-based SQLi
run_test "UNION SELECT basic" \
    "http://localhost:8081/?id=1+UNION+SELECT+1,2,3--" "403"

run_test "UNION ALL SELECT" \
    "http://localhost:8081/?id=1+UNION+ALL+SELECT+null,null,null--" "403"

# Time-based blind SQLi
run_test "MySQL SLEEP()" \
    "http://localhost:8081/?id=1'+AND+SLEEP(5)--" "403"

run_test "MySQL BENCHMARK()" \
    "http://localhost:8081/?id=1'+AND+BENCHMARK(10000000,SHA1('test'))--" "403"

run_test "PostgreSQL pg_sleep()" \
    "http://localhost:8081/?id=1';SELECT+pg_sleep(5)--" "403"

run_test "MSSQL WAITFOR DELAY" \
    "http://localhost:8081/?id=1';WAITFOR+DELAY+'0:0:5'--" "403"

# Command execution
run_test "MSSQL xp_cmdshell" \
    "http://localhost:8081/?id=1;EXEC+xp_cmdshell+'dir'" "403"

run_test "MSSQL exec master" \
    "http://localhost:8081/?id=1;EXEC+master.dbo.xp_cmdshell+'dir'" "403"

# Error-based SQLi
run_test "ExtractValue()" \
    "http://localhost:8081/?id=1+AND+extractvalue(1,concat(0x7e,version()))--" "403"

run_test "UpdateXML()" \
    "http://localhost:8081/?id=1+AND+updatexml(1,concat(0x7e,version()),1)--" "403"

# Information schema
run_test "information_schema" \
    "http://localhost:8081/?id=1+UNION+SELECT+table_name+FROM+information_schema.tables--" "403"

# Stacked queries
run_test "Stacked query DROP" \
    "http://localhost:8081/?id=1;DROP+TABLE+users--" "403"

run_test "Stacked query INSERT" \
    "http://localhost:8081/?id=1;INSERT+INTO+users+VALUES(1,'admin')--" "403"

# Boolean-based / tautology
run_test "OR 1=1" \
    "http://localhost:8081/?id=1'+OR+'1'='1" "403"

# Auth bypass
run_test "Auth bypass single quote" \
    "http://localhost:8081/?user=admin'--" "403"

# JSON-based SQLi
run_test "JSON_EXTRACT" \
    "http://localhost:8081/?id=1+AND+json_extract('{\"a\":1}','\$.a')=1--" "403"

# File operations
run_test "LOAD_FILE()" \
    "http://localhost:8081/?id=1+UNION+SELECT+load_file('/etc/passwd')--" "403"

run_test "INTO OUTFILE" \
    "http://localhost:8081/?id=1+INTO+OUTFILE+'/tmp/shell.php'--" "403"

# Base64 encoded SQLi
B64_PAYLOAD=$(echo -n "1 UNION SELECT 1,2,3--" | base64)
run_test "Base64 encoded UNION" \
    "http://localhost:8081/?id=$B64_PAYLOAD" "403"

# SQLite
run_test "sqlite_master" \
    "http://localhost:8081/?id=1+UNION+SELECT+sql+FROM+sqlite_master--" "403"

echo ""
echo -e "${BLUE}--- False Positive Tests (should NOT block = 200) ---${NC}"

# Normal inputs
run_test "Normal text search" \
    "http://localhost:8081/?name=John+Smith" "200"

run_test "Normal number" \
    "http://localhost:8081/?page=42" "200"

run_test "Normal path" \
    "http://localhost:8081/products/category/electronics" "200"

echo ""
echo -e "${BLUE}--- Results Summary ---${NC}"
TOTAL=$((PASS + FAIL))
echo -e "  Total: $TOTAL | ${GREEN}Passed: $PASS${NC} | ${RED}Failed: $FAIL${NC}"
echo ""

# Step 5: Run GoTestWAF
echo -e "${YELLOW}[5/7] Running GoTestWAF...${NC}"
echo "This may take several minutes..."
docker compose run --rm gotestwaf || {
    echo -e "${YELLOW}GoTestWAF completed with warnings (this may be normal)${NC}"
}

# Step 6: Show results
echo ""
echo -e "${YELLOW}[6/7] Test Complete!${NC}"
echo ""
echo "============================================================"
echo "RESULTS"
echo "============================================================"
echo ""
echo "Manual Tests: $PASS/$TOTAL passed"
echo ""
echo "HTML Report: $(ls -t reports/*.html 2>/dev/null | head -1 || echo 'Not generated')"
echo "Audit Log:   logs/modsec_audit.log"
echo "Error Log:   logs/error.log"
echo ""
echo "To view rule matches:"
echo "  grep -E 'id \"300[0-9]{3}\"' logs/modsec_audit.log"
echo ""

# Step 7: Extract GoTestWAF SQLi results
echo -e "${YELLOW}[7/7] Extracting SQLi-specific results...${NC}"
if [ -f logs/modsec_audit.log ]; then
    RULE_MATCHES=$(grep -cE 'id "300[0-9]{3}"' logs/modsec_audit.log 2>/dev/null || echo "0")
    echo "  Custom SQLi rule matches in audit log: $RULE_MATCHES"
fi
echo ""
echo "To stop containers:"
echo "  docker compose down"
echo ""
