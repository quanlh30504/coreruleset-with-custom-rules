# XSS Rule Test Environment

Testing environment for the new generalized XSS detection rules (`REQUEST-941-APPLICATION-CUSTOM-ATTACK-XSS-GENERALIZED.conf`).

## Rule IDs
- **200000**: Configuration variables
- **200001-200004**: Layer 1 - Standard XSS detection  
- **200005-200007**: Layer 2 - Nested Base64 detection
- **200008-200014**: Layer 3 - Mixed encoding detection

## Quick Start

```bash
# Run full test suite
./run_test.sh

# Or manually:
docker compose up -d waf backend
docker compose run --rm gotestwaf
```

## Manual XSS Test

```bash
# Should return HTTP 403 (blocked)
curl -v "http://localhost:8080/?test=<script>alert(1)</script>"
```

## View Results

- **HTML Report**: `reports/xss-rule-test-report*.html`
- **Audit Log**: `logs/modsec_audit.log`
- **Error Log**: `logs/error.log`

```bash
# Check rule matches
grep -E 'id "200[0-9]{3}"' logs/modsec_audit.log
```

## Cleanup

```bash
docker compose down
```
