#!/bin/bash
# XSS Rule Test Script
# Tests the new generalized XSS rules using GoTestWAF

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "============================================================"
echo "XSS Rule Testing Environment"
echo "Rule: REQUEST-941-APPLICATION-CUSTOM-ATTACK-XSS-GENERALIZED"
echo "Rule IDs: 200000-200014"
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
echo -e "${YELLOW}[1/6] Stopping any existing containers...${NC}"
docker compose down --remove-orphans 2>/dev/null || true

# Step 2: Start WAF and backend
echo -e "${YELLOW}[2/6] Starting WAF and backend containers...${NC}"
docker compose up -d waf backend

# Step 3: Wait for WAF to be healthy
echo -e "${YELLOW}[3/6] Waiting for WAF to be ready...${NC}"
MAX_WAIT=60
WAIT_COUNT=0
while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    if curl -s http://localhost:8080/ > /dev/null 2>&1; then
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

# Step 4: Quick manual test
echo ""
echo -e "${YELLOW}[4/6] Running quick XSS detection test...${NC}"
echo "Sending XSS payload: <script>alert(1)</script>"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/?test=<script>alert(1)</script>" 2>/dev/null || echo "000")
if [ "$RESPONSE" = "403" ]; then
    echo -e "${GREEN}✓ XSS payload blocked (HTTP 403) - WAF is working!${NC}"
elif [ "$RESPONSE" = "200" ]; then
    echo -e "${RED}✗ XSS payload NOT blocked (HTTP 200) - Check configuration${NC}"
else
    echo -e "${YELLOW}! Response code: $RESPONSE${NC}"
fi

# Step 5: Run GoTestWAF
echo ""
echo -e "${YELLOW}[5/6] Running GoTestWAF...${NC}"
echo "This may take several minutes..."
docker compose run --rm gotestwaf || {
    echo -e "${YELLOW}GoTestWAF completed with warnings (this may be normal)${NC}"
}

# Step 6: Show results
echo ""
echo -e "${YELLOW}[6/6] Test Complete!${NC}"
echo ""
echo "============================================================"
echo "RESULTS"
echo "============================================================"
echo ""
echo "HTML Report: $(ls -t reports/*.html 2>/dev/null | head -1 || echo 'Not generated')"
echo "Audit Log: logs/modsec_audit.log"
echo "Error Log: logs/error.log"
echo ""
echo "To view logs:"
echo "  cat logs/modsec_audit.log"
echo ""
echo "To check for rule 200xxx matches:"
echo "  grep -E 'id \"200[0-9]{3}\"' logs/modsec_audit.log"
echo ""
echo "To stop containers:"
echo "  docker compose down"
echo ""
