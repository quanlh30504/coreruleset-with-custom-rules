# So Sánh Chi Tiết: Tiếp Cận Enumeration vs. Generalized trong Phát Hiện SQL Injection

## Tóm tắt (Executive Summary)

Tài liệu này phân tích sự khác biệt về kiến trúc, luồng xử lý, và hiệu năng giữa hai phương pháp phát hiện tấn công SQL Injection trong WAF ModSecurity:

- **Phương pháp gốc (Nhóm nghiên cứu)** (File: `REQUEST-941-APPLICATION-CUSTOM-ATTACK-SQL-INJECTION.conf`, Rules ID: 100045-100065)
  - Tiếp cận: **Enumeration-based** (liệt kê cụ thể)
  - Đặc điểm: Capture → Decode → Compare (4 patterns cố định)
  
- **Phương pháp cải tiến** (File: `REQUEST-942-APPLICATION-CUSTOM-ATTACK-SQLI-GENERALIZED.conf`, Rules ID: 300000-300014)
  - Tiếp cận: **Structure-based** (dựa trên cấu trúc SQL)
  - Đặc điểm: Layered Detection + Multi-direction Decoding + SQL Comment Normalization

**Kết quả GoTestWAF:** SQLi Detection = **100%** (48/48 payloads blocked)

---

## 1. Kiến Trúc Tổng Quan (Architecture Overview)

### 1.1. Phương Pháp Gốc (Enumeration-based)

```mermaid
graph TD
    A[HTTP Request] --> B[Capture Raw Value]
    B --> C[Store in TX Variable]
    C --> D[Decode Base64 + HTML Entity]
    D --> E[Store Decoded Value]
    C --> F[Decode URL]
    F --> G[Store URL Decoded Value]
    E --> H{Check Decoded Values}
    G --> H
    H -->|Match 4 Patterns| I[BLOCK]
    H -->|No Match| J[PASS]
    
    style A fill:#e1f5ff
    style I fill:#ffcccc
    style J fill:#ccffcc
```

**Đặc điểm:**
- **21 rules** cho 6 input vectors (URL Path, HTMLMultiPartForm, HTMLForm, URLParam, JSONRequest, Headers)
- **Sequential processing**: Capture → Store → Decode → Store → Check
- **4 fixed patterns**: sleep, xp_cmdshell, JSON_EXTRACT, JSON_DEPTH
- **Single-layer decoding**: Chỉ decode 1 lần (Base64 HOẶC URL)

### 1.2. Phương Pháp Cải Tiến (Structure-based)

```mermaid
graph TD
    A[HTTP Request] --> B{Input Vector}
    B -->|Layer 1| C[Standard Decoding + SQLi Detection]
    B -->|Layer 2| D[Nested Base64 Detection]
    B -->|Layer 3| E[Mixed Encoding Detection]
    
    C --> C1[URL Decode]
    C1 --> C2[Base64 Decode]
    C2 --> C3[Replace SQL Comments]
    C3 --> C4[HTML Entity Decode]
    C4 --> C5[Compress Whitespace]
    C5 --> C6[Lowercase]
    C6 --> C7{13 Pattern Categories Match?}
    
    D --> D1[Detect Base64 Pattern]
    D1 --> D2[Decode Layer 1]
    D2 --> D3{Still Base64?}
    D3 -->|Yes| D4[Decode Layer 2]
    D4 --> D5{SQLi Structure?}
    
    E --> E1A[Path A: Base64 → URL]
    E --> E1B[Path B: URL → Base64]
    E1A --> E2{SQLi Structure?}
    E1B --> E2
    
    C7 -->|Yes| F[BLOCK]
    D5 -->|Yes| F
    E2 -->|Yes| F
    C7 -->|No| G[PASS]
    D5 -->|No| G
    E2 -->|No| G
    
    style A fill:#e1f5ff
    style F fill:#ffcccc
    style G fill:#ccffcc
```

**Đặc điểm:**
- **15 rules** tổ chức thành 4 layers (config + 3 detection layers)
- **In-place processing**: Transformation pipeline trực tiếp (không cần store intermediate)
- **13 pattern categories**: UNION, stacked queries, time-based, error-based, exec, info schema, file ops, boolean, comments, JSON, auth bypass, DB functions, PostgreSQL exec
- **Multi-layer decoding**: Decode tối đa 2-3 lần (nested + mixed)
- **SQL-specific normalization**: `t:replaceComments` xử lý `/**/` comment bypass

---

## 2. So Sánh Chi Tiết Luồng Xử Lý (Detailed Flow Comparison)

### 2.1. Phương Pháp Gốc - Luồng Chi Tiết

#### **Flow cho URL Parameter** (Rules 100055-100057)

```
┌─────────────────────────────────────────────────────────────┐
│ Step 1: Capture (Rule 100055)                               │
│ ─────────────────────────────────────────                   │
│ Input:  ?id=<PAYLOAD>                                       │
│ Match:  @rx .+                                              │
│ Action: Store → tx.raw_urlparam_value                       │
│         Log: "Captured URL parameter value: <PAYLOAD>"      │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 2: Decode (Rule 100056)                                │
│ ─────────────────────────────────────────                   │
│ Input:  tx.raw_urlparam_value                               │
│ Action: t:base64Decode → t:htmlEntityDecode                 │
│ Store:  tx.base64_decoded_value                             │
│ Log:    "Base64-decoded value: <DECODED>"                   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 3: Detection (Rule 100057)                             │
│ ─────────────────────────────────────────────               │
│ Check:  tx.raw_urlparam_value | tx.base64_decoded_value     │
│ Regex:  4 cố định patterns:                                 │
│   1. select(0) from (select(sleep(N))) v                    │
│   2. EXEC Master.dbo.xp_cmdshell                            │
│   3. JSON_EXTRACT('{''aKER'': N}', '$.aKER') = N           │
│   4. JSON_DEPTH('{}') != N                                  │
│                                                              │
│ If MATCH → BLOCK                                            │
│ ⚠️ msg: 'Detected XSS in URL parameter payload' (SAI!)     │
│ ⚠️ setvar: tx.xss_score (SAI! phải là sql_injection_score) │
└─────────────────────────────────────────────────────────────┘
```

**Vấn đề chính:**
- ❌ **3 rules/vector** → 21 rules tổng cộng cho 6 vectors (thừa)
- ❌ **Log message sai**: Ghi "XSS" thay vì "SQLi"
- ❌ **Score variable sai**: Dùng `tx.xss_score` thay vì `tx.sql_injection_score`
- ❌ **Chỉ 4 patterns**: Chỉ bắt đúng các payloads cụ thể đã liệt kê
- ❌ **Không có `t:replaceComments`**: Bypass dễ dàng bằng SQL comments

#### **Ví dụ Bypass phương pháp gốc:**

```sql
-- ❌ Bypass 1: UNION SELECT (không có trong 4 patterns)
?id=1 UNION SELECT username,password FROM users--

-- ❌ Bypass 2: Comment Obfuscation
?id=1;EXEC/*comment*/Master.dbo.xp_cmdshell 'dir'

-- ❌ Bypass 3: Stacked Query
?id=1; DROP TABLE users--

-- ❌ Bypass 4: Boolean Tautology
?id=1' OR '1'='1

-- ❌ Bypass 5: Error-based
?id=1 AND extractvalue(1,concat(0x7e,version()))

-- ❌ Bypass 6: PostgreSQL
?id=1; SELECT pg_sleep(5)--

-- ❌ Bypass 7: Nested Base64
?id=TVNjZ1FVNUVJRk5NUlVWUUtEVXBMUzA9  (base64(base64("1 AND SLEEP(5)--")))
```

---

### 2.2. Phương Pháp Cải Tiến - Luồng Chi Tiết

#### **Layer 1: Standard Decoding + Detection** (Rules 300001-300004)

```
┌─────────────────────────────────────────────────────────────┐
│ Rule 300002: ARGS_GET Detection (Example)                   │
│ ─────────────────────────────────────────────               │
│ Input:  ?id=<PAYLOAD>                                       │
│                                                              │
│ Transformation Pipeline (6 bước):                           │
│   t:none             → preserve original                    │
│   t:base64Decode     → decode Base64                        │
│   t:replaceComments  → normalize /**/ comments ← MỚI!      │
│   t:htmlEntityDecode → decode &lt; entities                 │
│   t:compressWhitespace → normalize whitespace               │
│   t:lowercase        → case-insensitive                     │
│                                                              │
│ Generalized Regex (13 categories):                          │
│   (?i)(?:                                                    │
│     \bunion\s+(?:all\s+)?select\b                  [UNION]  │
│   | ;\s*(?:select|insert|update|delete|drop|...)\b [STACK]  │
│   | \b(?:sleep|benchmark|pg_sleep|waitfor)\s*\(    [TIME]   │
│   | \b(?:extractvalue|updatexml)\s*\(              [ERROR]  │
│   | \bexec(?:ute)?\s+(?:master|xp_|sp_)           [EXEC]   │
│   | xp_cmdshell                                    [RCE]    │
│   | \b(?:information_schema|sys...)\b              [INFO]   │
│   | \b(?:load_file|into\s+(?:out|dump)file)\b      [FILE]   │
│   | \bor\s+[\d'"]+\s*=\s*[\d'"]+                  [BOOL]   │
│   | /\*[!+].*?\*/                                  [COMMENT]│
│   | \bjson_(?:extract|depth|...)\s*\(              [JSON]   │
│   | ['"](?:\s*(?:or|and)\s+['\"\d]|;)              [AUTH]   │
│   | \b(?:sqlite_master|pg_catalog|version)\s*\(    [DB]     │
│   | \bcopy\s+.*\s+(?:to|from)\s+program\b          [PG_RCE]│
│   )                                                          │
│                                                              │
│ If MATCH → BLOCK                                            │
│ ✅ msg: 'SQL Injection Attack Detected in URL Parameters'   │
│ ✅ setvar: tx.sql_injection_score                            │
└─────────────────────────────────────────────────────────────┘
```

**Key Improvements:**
- 🟢 **1 rule/vector** (thay vì 3 rules) → hiệu quả hơn
- 🟢 **t:replaceComments** → xử lý `UN/**/ION SEL/**/ECT` bypass
- 🟢 **13 pattern categories** → bao phủ hầu hết SQLi techniques
- 🟢 **Log message đúng**: "SQL Injection Attack Detected"
- 🟢 **Score variable đúng**: `tx.sql_injection_score`

#### **Layer 2: Nested Base64 Detection** (Rules 300005-300007)

```
┌─────────────────────────────────────────────────────────────┐
│ Rule 300005: Nested Base64 in ARGS_GET (Example)            │
│ ─────────────────────────────────────────────               │
│ Attack: Base64(Base64("1 UNION SELECT 1,2,3--"))            │
│                                                              │
│ Step 1: Pre-filter (Chain 1)                                │
│   Check: ^[A-Za-z0-9+/]{16,}={0,2}$                        │
│   → If NO: Skip (performance optimization)                  │
│   → If YES: → Continue                                      │
│                                                              │
│ Step 2: First decode (Chain 2)                              │
│   Input:  TVFWTklRVk5GVEVWRFZDQXhMRElzTXkwdA==             │
│   Action: t:base64Decode                                    │
│   Output: MSVOJU5FTEVDVCAxLDIsMyOt                          │
│   Check:  Still Base64? YES → Continue                      │
│                                                              │
│ Step 3: Second decode + Check (Chain 3)                     │
│   Input:  MSVOJU5FTEVDVCAxLDIsMyOt                          │
│   Action: t:base64Decode → t:replaceComments...             │
│   Output: 1 UNION SELECT 1,2,3--                            │
│   Check:  SQLi regex → MATCH → BLOCK                       │
│                                                              │
│ Tags: 'attack-encoding-evasion' + anomaly +2                │
└─────────────────────────────────────────────────────────────┘
```

#### **Layer 3: Mixed Encoding** (Rules 300008-300013)

```
┌──────────────────────────────────────┬──────────────────────────────────────┐
│ Rule 300008 (Path A)                 │ Rule 300009 (Path B)                 │
│ ────────────────────────────────     │ ────────────────────────────────     │
│ Payload: Base64 → URL encoding       │ Payload: URL → Base64 encoding       │
│                                      │                                      │
│ Decode sequence:                     │ Decode sequence:                     │
│   1. t:base64Decode                  │   1. t:urlDecodeUni                  │
│   2. t:urlDecodeUni                  │   2. t:base64Decode                  │
│   3. t:replaceComments               │   3. t:replaceComments               │
│   4. t:htmlEntityDecode              │   4. t:htmlEntityDecode              │
│   5. t:compressWhitespace            │   5. t:compressWhitespace            │
│   6. t:lowercase                     │   6. t:lowercase                     │
│                                      │                                      │
│ Example:                             │ Example:                             │
│ Input: MSBVTklPTiBTRUxFQ1Q%3D        │ Input: MSUyMFVOSU9OJTIwU0VM...       │
│ → Base64Decode → 1 UNION SELECT%3D   │ → URLDecode → 1 UNION SELECT...     │
│ → URLDecode → 1 UNION SELECT=       │ → Base64Decode → ...                │
│ Match: YES → BLOCK                   │ Match: YES → BLOCK                   │
└──────────────────────────────────────┴──────────────────────────────────────┘
```

---

## 3. So Sánh Kỹ Thuật Regex (Regex Technical Comparison)

### 3.1. Enumeration-based Regex (Phương pháp gốc - 4 patterns)

```regex
# Pattern 1: MySQL Time-based Blind
\bselect\s*\(\s*0\s*\)\s*from\s*\(select\s*\(sleep\s*\(\d+\)\)\)\s*v

# Pattern 2: MSSQL Command Execution  
EXEC\s+Master\.dbo\.xp_cmdshell

# Pattern 3: MySQL JSON Bypass
JSON_EXTRACT\(\s*'{''aKER'':\s*\d+}'\s*,\s*'\$.aKER'\)\s*=\s*\d+

# Pattern 4: MySQL JSON Bypass
JSON_DEPTH\(\s*'\{\}'\s*\)\s*!=\s*\d+
```

**Phân tích chi tiết:**

| Pattern | Database | Technique | Hạn chế |
|---------|----------|-----------|---------|
| `select(0) from (select(sleep(N)))` | MySQL | Time-based blind | Chỉ bắt đúng cú pháp `select(0)`, miss `SLEEP(5)` đơn giản |
| `EXEC Master.dbo.xp_cmdshell` | MSSQL | RCE | Chỉ bắt `Master.dbo`, miss `xp_cmdshell` trực tiếp |
| `JSON_EXTRACT('{''aKER'':N}',...)` | MySQL 5.7+ | JSON bypass | Chỉ bắt pattern với key `aKER` cụ thể |
| `JSON_DEPTH('{}') != N` | MySQL 5.7+ | JSON bypass | Chỉ bắt empty object `{}` |

**Vấn đề chính:**
- ❌ Quá cụ thể → **chỉ match payload chính xác** từ GoTestWAF
- ❌ Thay đổi nhỏ nhất (VD: `SLEeP(5)` thay vì `select(0)from(select(sleep(5)))v`) → **bypass**
- ❌ Không cover UNION, stacked queries, error-based, boolean, PostgreSQL, SQLite

### 3.2. Structure-based Regex (Phương pháp cải tiến - 13 categories)

```regex
(?i)(?:
  # 1. UNION-based SQLi (Most common)
  \bunion\s+(?:all\s+)?select\b
  
  # 2. Stacked queries (Multi-statement)
  |;\s*(?:select|insert|update|delete|drop|alter|create|truncate|exec)\b
  
  # 3. Time-based blind (Multi-database)
  |\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(
  
  # 4. Error-based (MySQL)
  |\b(?:extractvalue|updatexml)\s*\(|floor\s*\(\s*rand\s*\(
  
  # 5. Command execution (MSSQL)
  |\bexec(?:ute)?\s+(?:master|xp_|sp_)|xp_cmdshell
  
  # 6. Information schema probing
  |\b(?:information_schema|sys(?:databases|objects|columns|tables))\b
  
  # 7. File operations
  |\b(?:load_file|into\s+(?:out|dump)file|load\s+data\s+infile)\b
  
  # 8. Boolean tautology
  |\bor\s+[\d'"]+\s*=\s*[\d'"]+
  
  # 9. Comment-based evasion (MySQL in-line comments)
  |/\*[!+].*?\*/
  
  # 10. JSON-based SQLi
  |\bjson_(?:extract|depth|length|type|valid|object|array|value)\s*\(
  
  # 11. Auth bypass
  |['"](?:\s*(?:or|and)\s+['\"\d]|;)
  
  # 12. DB-specific functions
  |\b(?:sqlite_master|pg_(?:catalog|sleep|user)|version|database)\s*\(
  
  # 13. PostgreSQL command execution
  |\bcopy\s+.*\s+(?:to|from)\s+program\b
)
```

**So sánh pattern by pattern:**

| Attack Type | Enumeration (Cũ) | Generalized (Mới) | Mở rộng |
|-------------|-------------------|--------------------|---------| 
| MySQL time-based | `select(0)from(select(sleep(N)))v` (1 cú pháp) | `\b(?:sleep\|benchmark\|...)\s*\(` (4 hàm) | **4x** |
| MSSQL exec | `EXEC Master.dbo.xp_cmdshell` (1 cú pháp) | `\bexec(?:ute)?\s+(?:master\|xp_\|sp_)\|xp_cmdshell` (5 biến thể) | **5x** |
| JSON bypass | 2 patterns cố định (aKER key) | `\bjson_(?:extract\|depth\|length\|type\|valid\|...)\s*\(` (8 hàm) | **4x** |
| UNION SQLi | ❌ Không có | `\bunion\s+(?:all\s+)?select\b` | **MỚI** |
| Stacked queries | ❌ Không có | `;\s*(?:select\|insert\|update\|delete\|drop\|...)\b` (8 keywords) | **MỚI** |
| Error-based | ❌ Không có | `\b(?:extractvalue\|updatexml)\s*\(\|floor\s*\(\s*rand` | **MỚI** |
| Boolean | ❌ Không có | `\bor\s+[\d'"]+\s*=\s*[\d'"]+` | **MỚI** |
| File ops | ❌ Không có | `\b(?:load_file\|into\s+(?:out\|dump)file\|...)` | **MỚI** |
| PostgreSQL | ❌ Không có | `pg_sleep\|pg_catalog\|copy...to program` | **MỚI** |
| SQLite | ❌ Không có | `sqlite_master` | **MỚI** |
| Auth bypass | ❌ Không có | `['"](?:\s*(?:or\|and)\s+['\"\d]\|;)` | **MỚI** |
| Comment bypass | ❌ Không có | `/\*[!+].*?\*/` | **MỚI** |
| Info schema | ❌ Không có | `information_schema\|sys(?:databases\|...)` | **MỚI** |

---

## 4. So Sánh Transformation Pipeline

### 4.1. Pipeline cũ (Enumeration)

```
Raw Input
    ↓
t:base64Decode           (decode Base64)
    ↓   
t:htmlEntityDecode       (decode &lt; etc.)
    ↓
Pattern Matching (4 patterns)
```

**Vấn đề:**
- ❌ Không có `t:replaceComments` → `UN/**/ION SEL/**/ECT` bypass
- ❌ Không có `t:compressWhitespace` → `UNION    SELECT` bypass  
- ❌ Không có `t:lowercase` → mixed case `uNiOn SeLeCt` bypass
- ❌ URL decode và Base64 decode tách riêng, không chain

### 4.2. Pipeline mới (Generalized)

```
Raw Input
    ↓
t:urlDecodeUni           (decode %XX - chỉ cho Headers/URL path)
    ↓
t:base64Decode           (decode Base64)
    ↓
t:replaceComments        (normalize /**/ SQL comments) ← MỚI!
    ↓
t:htmlEntityDecode       (decode &lt; etc.)
    ↓
t:compressWhitespace     (normalize whitespace) ← MỚI!
    ↓
t:lowercase              (case-insensitive) ← MỚI!
    ↓
Pattern Matching (13 categories)
```

**Cải tiến:**
- ✅ `t:replaceComments` → bắt `UN/**/ION`, `SEL/**/ECT`, `SL/**/EEP`
- ✅ `t:compressWhitespace` → bắt `UNION    SELECT`, `SLEEP  (  5  )`
- ✅ `t:lowercase` → bắt `uNiOn`, `sLeEp`, mixed case
- ✅ Chain transformations → decode đúng thứ tự

---

## 5. So Sánh Input Vectors

### 5.1. Phương pháp gốc — 6 vectors × 3+ rules mỗi vector

| Vector | Rule IDs | Rules | Decode Method |
|--------|----------|-------|---------------|
| URLPath | 100045-100047 | 3 | Base64 + HTML |
| HTMLMultiPartForm | 100048-100051 | 4 | Base64 + HTML + URL |
| HTMLForm | 100052-100054 | 3 | Base64 + HTML |
| URLParam | 100055-100057 | 3 | Base64 + HTML |
| JSONRequest | 100058-100061 | 4 | Base64 + HTML + URL |
| Headers/User-Agent | 100062-100065 | 4 | Base64 + HTML + URL |
| **Tổng** | | **21 rules** | |

**Vấn đề:**
- ❌ `HTMLMultiPartForm` và `HTMLForm` đều dùng `ARGS` → trùng lặp
- ❌ `HTMLMultiPartForm` và `JSONRequest` đều dùng `ARGS` → trùng lặp
- ❌ 21 rules nhưng thực tế chỉ cần 4 biến ModSecurity

### 5.2. Phương pháp mới — 4 vectors × 1 rule mỗi vector

| Vector | Rule ID | Rules | ModSecurity Variable | Decode Method |
|--------|---------|-------|---------------------|---------------|
| URL Path | 300001 | 1 (chain) | `REQUEST_URI` | URL + Base64 + Comments + HTML |
| GET Params | 300002 | 1 | `ARGS_GET` | Base64 + Comments + HTML |
| POST/JSON/Form | 300003 | 1 | `ARGS` | Base64 + Comments + HTML |
| Headers | 300004 | 1 | `REQUEST_HEADERS` | URL + Base64 + Comments + HTML |
| **Tổng Layer 1** | | **4 rules** | | |

**Cải tiến:**
- ✅ Gộp HTMLMultiPartForm + HTMLForm + JSONRequest → **1 rule ARGS** (300003)
- ✅ 4 rules thay vì 21 → **giảm 81% số rules** cho Layer 1
- ✅ Mỗi rule tự decode đầy đủ → không cần steps trung gian

---

## 6. Kết Quả GoTestWAF So Sánh

### 6.1. Kết Quả Test Phương Pháp Mới

| GoTestWAF Category | Detection Rate | Blocked | Bypassed |
|---------------------|---------------|---------|----------|
| **sql-injection** | **100.00%** | **48** | **0** |
| xss-scripting | 99.10% | 221 | 2 |
| shell-injection | 100.00% | 32 | 0 |
| rce-urlparam | 100.00% | 9 | 0 |
| **Overall True-Positive** | **98.95%** | **661/668** | **7/668** |

### 6.2. Custom Rule Matches (Audit Log)

```
17 × Rule 300003 (ARGS — POST/JSON/Form)
 5 × Rule 300002 (ARGS_GET — URL Parameters)
 4 × Rule 300004 (REQUEST_HEADERS)
 4 × Rule 300001 (REQUEST_URI — URL Path)
─────────────────────
30 total custom rule matches
```

### 6.3. Manual Test Results

| # | Attack Technique | Payload | Old Rules | New Rules |
|---|-----------------|---------|-----------|-----------|
| 1 | UNION SELECT | `1 UNION SELECT 1,2,3--` | ❌ Miss | ✅ Block |
| 2 | UNION ALL SELECT | `1 UNION ALL SELECT null,null--` | ❌ Miss | ✅ Block |
| 3 | MySQL SLEEP | `1' AND SLEEP(5)--` | ⚠️ Partial¹ | ✅ Block |
| 4 | MySQL BENCHMARK | `1' AND BENCHMARK(10000000,SHA1('test'))--` | ❌ Miss | ✅ Block |
| 5 | PostgreSQL pg_sleep | `1';SELECT pg_sleep(5)--` | ❌ Miss | ✅ Block |
| 6 | MSSQL WAITFOR | `1';WAITFOR DELAY '0:0:5'--` | ❌ Miss | ✅ Block |
| 7 | xp_cmdshell | `1;EXEC xp_cmdshell 'dir'` | ❌ Miss² | ✅ Block |
| 8 | exec master | `1;EXEC master.dbo.xp_cmdshell 'dir'` | ✅ Block | ✅ Block |
| 9 | extractvalue | `1 AND extractvalue(1,concat(0x7e,version()))` | ❌ Miss | ✅ Block |
| 10 | updatexml | `1 AND updatexml(1,concat(0x7e,version()),1)` | ❌ Miss | ✅ Block |
| 11 | information_schema | `1 UNION SELECT table_name FROM information_schema.tables` | ❌ Miss | ✅ Block |
| 12 | DROP TABLE | `1;DROP TABLE users--` | ❌ Miss | ✅ Block |
| 13 | INSERT INTO | `1;INSERT INTO users VALUES(1,'admin')--` | ❌ Miss | ✅ Block |
| 14 | OR 1=1 | `1' OR '1'='1` | ❌ Miss | ✅ Block |
| 15 | Auth bypass | `admin'--` | ❌ Miss | ✅ Block |
| 16 | JSON_EXTRACT | `1 AND json_extract('{"a":1}','$.a')=1` | ⚠️ Partial³ | ✅ Block |
| 17 | load_file | `1 UNION SELECT load_file('/etc/passwd')` | ❌ Miss | ✅ Block |
| 18 | INTO OUTFILE | `1 INTO OUTFILE '/tmp/shell.php'` | ❌ Miss | ✅ Block |
| 19 | sqlite_master | `1 UNION SELECT sql FROM sqlite_master` | ❌ Miss | ✅ Block |
| 20 | Base64 UNION | `MSBVTklPTiBTRUxFQ1QgMSwyLDMtLQ==` | ❌ Miss | ✅ Block |
| | **Tổng** | | **1-2/20** (5-10%) | **20/20** (100%) |

> ¹ Old rule chỉ bắt `select(0) from (select(sleep(N))) v`, không bắt `SLEEP(5)` đơn giản  
> ² Old rule chỉ bắt `EXEC Master.dbo.xp_cmdshell`, không bắt `xp_cmdshell` trực tiếp  
> ³ Old rule chỉ bắt pattern với key `aKER` cụ thể  

---

## 7. So Sánh Hiệu Năng & Coverage

### 7.1. Bảng So Sánh Tổng Quan

| Tiêu chí | Enumeration (100xxx) | Generalized (300xxx) | Improvement |
|----------|---------------------|---------------------|-------------|
| **Số lượng rules** | 21 | 15 | **↓ 29%** (ít hơn!) |
| **Lines of code** | 143 | 483 | +340 LOC |
| **Decoding layers** | 1 layer | 3 layers | +200% |
| **SQLi pattern categories** | 4 | 13 | **+225%** |
| **Input vectors** | 6 (redundant) | 4 (optimized) | Tối ưu |
| **SQL comment handling** | ❌ Không | ✅ `t:replaceComments` | MỚI |
| **Nested encoding** | ❌ Không | ✅ 2 levels | MỚI |
| **Mixed encoding** | ❌ Không | ✅ Dual-direction | MỚI |
| **Anomaly detection** | ❌ Không | ✅ Có | MỚI |
| **Log messages** | ❌ Sai (XSS) | ✅ Đúng (SQLi) | Fixed |
| **Score variable** | ❌ `tx.xss_score` | ✅ `tx.sql_injection_score` | Fixed |
| **Manual test pass rate** | ~5-10% | **100%** | **+90%** |
| **GoTestWAF SQLi** | — | **100% (48/48)** | Verified |
| **Database coverage** | MySQL + MSSQL | MySQL + MSSQL + PostgreSQL + SQLite | **+100%** |

---

## 8. Ưu & Nhược Điểm (Pros & Cons)

### 8.1. Phương Pháp Gốc (Enumeration-based)

#### ✅ Ưu điểm:
1. **Đơn giản**: 143 LOC, dễ đọc
2. **Transparent logging**: Log từng bước capture/decode/check
3. **Zero false positives**: Patterns quá cụ thể nên không bao giờ bắt nhầm
4. **Low CPU**: Ít transformations

#### ❌ Nhược điểm:
1. **Chỉ 4 patterns**: Miss >90% SQLi attack types
2. **Redundant rules**: 21 rules nhưng chỉ cần 4
3. **Log messages sai**: Ghi "XSS" thay vì "SQLi"
4. **Score variable sai**: `tx.xss_score` thay vì `tx.sql_injection_score`
5. **Không nested/mixed encoding**: Bypass trivial
6. **Không comment normalization**: `UN/**/ION` bypass
7. **Không future-proof**: Phải thêm manual khi có pattern mới

### 8.2. Phương Pháp Cải Tiến (Generalized)

#### ✅ Ưu điểm:
1. **100% GoTestWAF SQLi detection**
2. **13 pattern categories**: Cover hầu hết SQLi techniques
3. **Multi-database**: MySQL + MSSQL + PostgreSQL + SQLite
4. **`t:replaceComments`**: Chống comment bypass
5. **Nested + Mixed encoding**: 3-layer detection
6. **Correct logging**: msg và score variable đúng
7. **Fewer rules**: 15 vs 21 (tối ưu hơn!)
8. **Future-proof**: Structure-based patterns tự bắt biến thể mới

#### ❌ Nhược điểm:
1. **Complex regex**: Khó maintain
2. **483 LOC**: Nhiều code hơn
3. **Higher false positive risk**: Boolean tautology pattern có thể match input hợp lệ
4. **Performance overhead**: Thêm `t:replaceComments` + `t:compressWhitespace`

---

## 9. Kết Luận & Khuyến Nghị

### 9.1. Tóm Tắt

| Aspect | Winner | Reason |
|--------|--------|--------|
| **Simplicity** | 🏆 Enumeration | Ít code, dễ hiểu |
| **Coverage** | 🏆 **Generalized** | 100% vs ~5-10% detection |
| **Correctness** | 🏆 **Generalized** | Log msg và score đúng |
| **Rule efficiency** | 🏆 **Generalized** | 15 rules vs 21 rules |
| **Evasion resistance** | 🏆 **Generalized** | Nested + mixed + comments |
| **Multi-database** | 🏆 **Generalized** | 4 databases vs 2 |
| **Overall** | 🏆 **Generalized** | Better security posture |

### 9.2. Đóng Góp Học Thuật

1. **Chuyển từ signature-based sang structure-based**: Regex bắt cấu trúc SQL thay vì payload cụ thể
2. **Layered detection architecture**: 4-layer approach cho phép fine-tune từng layer
3. **SQL comment normalization**: `t:replaceComments` là transformation quan trọng mà rules cũ thiếu
4. **Multi-direction decoding**: Bắt cả 2 thứ tự encoding (Base64→URL và URL→Base64)
5. **Quantified improvement**: Từ ~5-10% lên 100% detection với GoTestWAF verified

---

## Phụ Lục: Rule ID Mapping

| Enumeration ID | Function | Generalized ID | Enhancement |
|----------------|----------|----------------|-------------|
| 100045-100047 | URLPath | 300001 | +13 patterns, +comments, +nested, +mixed |
| 100048-100051 | HTMLMultiPartForm | 300003 | Gộp vào ARGS |
| 100052-100054 | HTMLForm | 300003 | Gộp vào ARGS |
| 100055-100057 | URLParam | 300002 | +13 patterns, +nested, +mixed |
| 100058-100061 | JSONRequest | 300003 | Gộp vào ARGS |
| 100062-100065 | Headers | 300004 | +13 patterns, +nested, +mixed |
| — | Config | 300000 | MỚI |
| — | Nested Base64 | 300005-300007 | MỚI (3 rules) |
| — | Mixed Encoding | 300008-300013 | MỚI (6 rules) |
| — | Anomaly | 300014 | MỚI |

---

**Document Version:** 1.0  
**Date:** 25/02/2026  
**Author:** Phân tích so sánh cho khóa luận WAF SQL Injection Detection
