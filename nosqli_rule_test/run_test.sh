#!/bin/bash
# NoSQL Injection Rule Test Script
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

echo "============================================================"
echo "NoSQL Injection Rule Testing"
echo "Rule: REQUEST-944-APPLICATION-CUSTOM-ATTACK-NOSQL-GENERALIZED"
echo "Rule IDs: 400000-400014"
echo "============================================================"

cleanup() { echo -e "\n${YELLOW}Cleaning up...${NC}"; docker compose down --remove-orphans 2>/dev/null || true; }
trap cleanup EXIT

echo -e "${YELLOW}[1/6] Starting containers...${NC}"
docker compose down --remove-orphans 2>/dev/null || true
mkdir -p logs reports
docker compose up -d waf backend

echo -e "${YELLOW}[2/6] Waiting for WAF...${NC}"
for i in $(seq 1 30); do
    if curl -s http://localhost:8083/ > /dev/null 2>&1; then echo -e "${GREEN}WAF ready!${NC}"; break; fi
    sleep 2; echo "  Waiting... $((i*2))s"
done

PASS=0; FAIL=0
run_test() {
    local desc="$1" url="$2" expected="$3" method="${4:-GET}" data="$5"
    if [ "$method" = "POST" ]; then
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "$data" "$url" 2>/dev/null || echo "000")
    else
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    fi
    if [ "$RESPONSE" = "$expected" ]; then
        echo -e "  ${GREEN}✓ PASS${NC} - $desc (HTTP $RESPONSE)"; PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗ FAIL${NC} - $desc (HTTP $RESPONSE, expected $expected)"; FAIL=$((FAIL + 1))
    fi
}

echo -e "\n${YELLOW}[3/6] Running NoSQLi detection tests...${NC}"
echo -e "\n${BLUE}--- MongoDB Operator Injection (expect 403) ---${NC}"
run_test "MongoDB \$ne operator" "http://localhost:8083/?user[\$ne]=null&pass[\$ne]=null" "403"
run_test "MongoDB \$gt operator" "http://localhost:8083/?user=admin&pass[\$gt]=" "403"
run_test "MongoDB \$where operator" "http://localhost:8083/?q=\$where:%20function(){return%20true}" "403"
run_test "MongoDB \$regex operator" "http://localhost:8083/?user[\$regex]=admin.*" "403"
run_test "MongoDB \$exists operator" "http://localhost:8083/?user[\$exists]=true" "403"
run_test "MongoDB \$or logical" "http://localhost:8083/?q=\$or[{user:admin}]" "403"
run_test "MongoDB \$in operator" "http://localhost:8083/?role[\$in][]=admin&role[\$in][]=root" "403"

echo -e "\n${BLUE}--- MongoDB Auth Bypass (expect 403) ---${NC}"
run_test "Auth bypass \$ne:null POST" "http://localhost:8083/login" "403" "POST" 'user=admin&pass[$ne]=null'
run_test "Auth bypass \$gt:'' POST" "http://localhost:8083/login" "403" "POST" 'user=admin&pass[$gt]='

echo -e "\n${BLUE}--- JavaScript Injection (expect 403) ---${NC}"
run_test "JS function injection" "http://localhost:8083/?q=function(){return%20true}" "403"
run_test "JS eval()" "http://localhost:8083/?q=eval('process.exit()')" "403"
run_test "JS this.password" "http://localhost:8083/?q=this.password%3D%3D'admin'" "403"
run_test "JS require child_process" "http://localhost:8083/?q=require('child_process')" "403"

echo -e "\n${BLUE}--- MongoDB Commands (expect 403) ---${NC}"
run_test "db.users.find" "http://localhost:8083/?q=db.users.find({})" "403"
run_test "db.users.drop" "http://localhost:8083/?q=db.users.drop()" "403"
run_test "MongoDB ObjectId" "http://localhost:8083/?id=ObjectId('507f1f77bcf86cd799439011')" "403"

echo -e "\n${BLUE}--- MongoDB Update/Aggregation (expect 403) ---${NC}"
run_test "\$set operator" "http://localhost:8083/?update[\$set][role]=admin" "403"
run_test "\$push operator" "http://localhost:8083/?update[\$push][roles]=admin" "403"
run_test "\$group aggregation" "http://localhost:8083/?pipeline[\$group][_id]=null" "403"

echo -e "\n${BLUE}--- Redis Injection (expect 403) ---${NC}"
run_test "Redis FLUSHALL" "http://localhost:8083/?cmd=FLUSHALL" "403"
run_test "Redis CONFIG" "http://localhost:8083/?cmd=CONFIG%20SET%20dir%20/tmp" "403"
run_test "Redis EVAL" "http://localhost:8083/?cmd=EVAL%20'return%201'%200" "403"

echo -e "\n${BLUE}--- CouchDB Injection (expect 403) ---${NC}"
run_test "CouchDB _all_docs" "http://localhost:8083/_all_docs" "403"
run_test "CouchDB _find" "http://localhost:8083/_find" "403"

echo -e "\n${BLUE}--- Base64 Encoded NoSQLi (expect 403) ---${NC}"
B64=$(echo -n '{"$ne": null}' | base64)
run_test "Base64 \$ne:null" "http://localhost:8083/?pass=$B64" "403"

echo -e "\n${BLUE}--- False Positive Tests (expect 200) ---${NC}"
run_test "Normal text" "http://localhost:8083/?name=John+Smith" "200"
run_test "Normal number" "http://localhost:8083/?page=42" "200"
run_test "Normal path" "http://localhost:8083/products/electronics" "200"

echo -e "\n${BLUE}--- Results Summary ---${NC}"
TOTAL=$((PASS + FAIL))
echo -e "  Total: $TOTAL | ${GREEN}Passed: $PASS${NC} | ${RED}Failed: $FAIL${NC}"

echo -e "\n${YELLOW}[4/6] Running GoTestWAF...${NC}"
docker compose run --rm gotestwaf || echo -e "${YELLOW}GoTestWAF completed${NC}"

echo -e "\n${YELLOW}[5/6] Extracting results...${NC}"
if [ -f logs/modsec_audit.log ]; then
    MATCHES=$(grep -cE 'id "400[0-9]{3}"' logs/modsec_audit.log 2>/dev/null || echo "0")
    echo "  Custom NoSQLi rule matches: $MATCHES"
    echo "  Rule breakdown:"
    grep -oP 'id "400\d{3}"' logs/modsec_audit.log 2>/dev/null | sort | uniq -c | sort -rn || true
fi

echo -e "\n${YELLOW}[6/6] Done!${NC}"
echo "Manual: $PASS/$TOTAL passed"
echo "Report: $(ls -t reports/*.html 2>/dev/null | head -1 || echo 'N/A')"
echo "Audit:  logs/modsec_audit.log"
