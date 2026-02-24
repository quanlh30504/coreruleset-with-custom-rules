# BÁO CÁO TIẾN ĐỘ ĐỒ ÁN

**Sinh viên:** Quân  
**Đề tài:** Cải thiện khả năng phát hiện tấn công Injection của OWASP CRS bằng phương pháp Generalized Detection  
**Ngày:** 02/02/2026

---

## 1. Tổng Quan Bài Toán

### 1.1 Giới thiệu vấn đề đang gặp phải

Web Application Firewall (WAF) là tuyến phòng thủ quan trọng bảo vệ ứng dụng web khỏi các cuộc tấn công. **OWASP Core Rule Set (CRS)** là bộ rule phổ biến nhất cho ModSecurity WAF, tuy nhiên vẫn tồn tại nhiều hạn chế:

| Vấn đề | Mức độ nghiêm trọng |
|--------|---------------------|
| Chỉ phát hiện được **60%** tấn công có encoding | Cao |
| **264 payloads** bypass thành công trong test GoTestWAF | Cao |
| Kỹ thuật **Base64 encoding** bypass 84% cases | Cao |
| Nhiều loại **Injection attacks** không được detect | Rất cao |

**Phân bố bypass theo loại tấn công (OWASP A03:2021 - Injection):**

| Loại Injection | Số Bypass | Tỷ lệ |
|----------------|-----------|-------|
| Cross-Site Scripting (XSS) | 118 | 44.7% |
| NoSQL Injection | 27 | 10.2% |
| SQL Injection | 26 | 9.8% |
| LDAP Injection | 16 | 6.1% |
| Server-Side Include (SSI) | 13 | 4.9% |
| Server-Side Template Injection (SSTI) | 12 | 4.5% |
| Shell/OS Command Injection | 11 | 4.2% |
| Path Traversal/LFI | 11 | 4.2% |
| Mail Injection | 12 | 4.5% |
| XML/XXE Injection | 8 | 3.0% |
| RCE | 10 | 3.8% |
| **Tổng** | **264** | **100%** |

**Nguyên nhân chính:**
- OWASP CRS sử dụng phương pháp **enumeration-based** (liệt kê từng pattern cụ thể)
- Không xử lý tốt các kỹ thuật encoding bypass (Base64, URL encoding, Mixed encoding)
- Dễ bị bypass bằng các biến thể mới của tấn công
- Rules được thiết kế độc lập, thiếu tính tổng quát

### 1.2 Các mục tiêu đang được quan tâm

1. **Cải thiện tỷ lệ phát hiện TẤT CẢ Injection attacks** - Từ 60% lên >95%
2. **Xây dựng phương pháp Generalized Detection** - Áp dụng cho nhiều loại Injection
3. **Xử lý encoding bypass** - Base64, URL encoding, Mixed encoding cho tất cả attack types
4. **Không tăng False Positive** - Giữ nguyên hoặc giảm tỷ lệ cảnh báo sai
5. **Thiết kế modular** - Dễ mở rộng và bảo trì

---

## 2. Các Nghiên Cứu Liên Quan

### 2.1 Hướng đến giải quyết vấn đề gì?

Nghiên cứu của nhóm (Paper: "Computers & Security 160 (2026) 104714") hướng đến:
- Nâng cao khả năng phát hiện của OWASP CRS với **tất cả các loại tấn công Injection**
- Xử lý các kỹ thuật **encoding bypass** mà CRS mặc định không detect được
- Giảm **False Negative** (bỏ sót tấn công) mà không tăng **False Positive**

### 2.2 Cách làm và xử lý dữ liệu

**Dữ liệu test:**
- Sử dụng **GoTestWAF v0.5.6** - công cụ test WAF tự động
- **810 payloads** (669 độc hại + 141 hợp lệ)
- Bao phủ 11+ loại Injection attacks theo OWASP Top 10

**Phương pháp của nhóm nghiên cứu:**
```
┌─────────────────────────────────────────────────────────────────┐
│  NHÓM NGHIÊN CỨU - ENUMERATION-BASED APPROACH                  │
├─────────────────────────────────────────────────────────────────┤
│  1. Phân tích 264 bypass cases từ GoTestWAF                     │
│  2. Xác định pattern cụ thể cho từng loại tấn công              │
│  3. Viết 146 custom rules (12 files) bổ sung cho CRS            │
│  4. Xử lý encoding: Multiple decode chains                      │
│  5. Test lại với GoTestWAF để đánh giá                          │
└─────────────────────────────────────────────────────────────────┘
```

**Cấu trúc 146 custom rules của nhóm:**
```
📁 rules/
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-XSS.conf           (XSS)
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-SQL-INJECTION.conf (SQLi)
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-NOSQL-INJECTION.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-LDAP-INJECTION.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-SHELL-INJECTION.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-SST-INJECTION.conf (SSTI)
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-SS-INCLUDE.conf    (SSI)
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-PATH-TRAVERSAL.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-MAIL-INJECTION.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-RCE.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-RCE-URLPATH.conf
└── REQUEST-941-APPLICATION-CUSTOM-ATTACK-COM-UA.conf
```

**Kết quả đạt được:**

| Attack Type | Bypass trước | Bypass sau | Giảm |
|-------------|--------------|------------|------|
| XSS | 118 | 11 | 90.7% |
| NoSQL Injection | 27 | 0 | 100% |
| SQL Injection | 26 | 2 | 92.3% |
| LDAP Injection | 16 | 0 | 100% |
| SSI | 13 | 1 | 92.3% |
| SSTI | 12 | 0 | 100% |
| Path Traversal | 11 | 1 | 90.9% |
| Shell Injection | 11 | 0 | 100% |
| **Tổng** | **264** | **17** | **93.6%** |

**Detection rate: 63% → 97.5%**

### 2.3 Hạn chế của nghiên cứu

1. **Enumeration-based approach:**
   - Mỗi loại attack có file rules riêng, thiếu tính thống nhất
   - Cần update rules mỗi khi có pattern mới
   - Không tự động phát hiện biến thể mới
   - Còn 17 bypass chưa xử lý được (XSS: 11, SQLi: 2, SSI: 1, Path Traversal: 1, RCE: 2)

2. **Scope hạn chế:**
   - Chỉ test trong môi trường lab (Kali Linux VM)
   - Chưa test trên production environment
   - Phụ thuộc vào GoTestWAF payloads

3. **Maintenance overhead:**
   - 146 rules trong 12 files cần maintain riêng lẻ
   - Khó đảm bảo consistency giữa các files
   - Duplicate logic xử lý encoding

---

## 3. Tổng Quan Đề Xuất

### 3.1 Quy trình chung

```
┌─────────────────────────────────────────────────────────────────┐
│         GENERALIZED INJECTION DETECTION FRAMEWORK               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [Request] → [LAYER 0: Universal Capture & Decode]              │
│           → [LAYER 1: Multi-location Input Processing]          │
│           → [LAYER 2: Encoding Normalization]                   │
│           → [LAYER 3: Attack-specific Detection]                │
│                   ├── XSS Patterns                              │
│                   ├── SQLi Patterns                             │
│                   ├── NoSQLi Patterns                           │
│                   ├── Command Injection Patterns                │
│                   ├── LDAP/SSTI/SSI Patterns                    │
│                   └── Path Traversal Patterns                   │
│           → [LAYER 4: Advanced Bypass Detection]                │
│           → [Block/Allow Decision]                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Kiến trúc Layered Detection:**

| Layer | Mục đích | Áp dụng cho |
|-------|----------|-------------|
| 0 | Universal Capture & Decode | Tất cả Injection types |
| 1 | Multi-location Processing (ARGS, HEADERS, URI) | Tất cả Injection types |
| 2 | Encoding Normalization (Base64, URL, Mixed) | Tất cả Injection types |
| 3 | Attack-specific Generalized Patterns | Từng loại Injection |
| 4 | Advanced Bypass Detection | Tất cả Injection types |

### 3.2 Muốn giải quyết vấn đề gì? Bằng cách nào?

**Vấn đề cần giải quyết:**
- 17 bypass cases còn lại sau khi áp dụng rules của nhóm
- Tự động phát hiện các biến thể Injection mới
- Giảm công sức maintenance rules
- Tạo framework có thể mở rộng

**Giải pháp đề xuất - GENERALIZED APPROACH cho TẤT CẢ Injection types:**

| Loại Injection | Enumeration (Nhóm) | Generalized (Em) |
|----------------|-------------------|------------------|
| **XSS** | `<script>`, `<svg>`, `onclick`... | `<\s*\w+`, `on\w+\s*=` |
| **SQLi** | `UNION SELECT`, `OR 1=1`... | `(?:union|select|insert)\s+` |
| **NoSQLi** | `{$gt:}`, `{$ne:}`... | `\{\s*\$\w+\s*:` |
| **Command Inj** | `;cat`, `|whoami`... | `[;\|&]\s*\w+` |
| **LDAP** | `)(uid=*`, `admin)(&`... | `\)\s*\(?\s*\w+=` |
| **SSTI** | `{{7*7}}`, `${7*7}`... | `[\{$#]\{?\s*\w+` |
| **Path Traversal** | `../`, `..\\`... | `\.\.[\\/]` |

**Các pattern detection chính theo loại:**

```
┌─────────────────────────────────────────────────────────────────┐
│  GENERALIZED PATTERNS BY INJECTION TYPE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [XSS]                                                          │
│  ├── HTML Tags:      <\s*(?:script|svg|img|body|...)            │
│  ├── Event Handlers: on\w+\s*=                                  │
│  ├── JS Functions:   (?:alert|eval|Function)\s*[\(`]            │
│  └── DOM Sinks:      document\.|window\.|location\.             │
│                                                                 │
│  [SQL Injection]                                                │
│  ├── SQL Keywords:   (?:select|union|insert|update|delete)\s+   │
│  ├── SQL Operators:  \s+(?:or|and)\s+\d+\s*=\s*\d+              │
│  ├── SQL Comments:   (?:--|#|/\*)                               │
│  └── SQL Functions:  (?:concat|char|hex|unhex)\s*\(             │
│                                                                 │
│  [NoSQL Injection]                                              │
│  ├── MongoDB Ops:    \{\s*\$(?:gt|lt|ne|eq|regex|where)\s*:     │
│  ├── JS in NoSQL:    \$where\s*:\s*['\"].*function              │
│  └── Array Inject:   \[\s*\$\w+                                 │
│                                                                 │
│  [Command Injection]                                            │
│  ├── Cmd Separators: [;\|&`]\s*(?:cat|ls|whoami|id|nc|curl)     │
│  ├── Subshell:       \$\([^)]+\)|\`[^`]+\`                      │
│  └── Reverse Shell:  nc\s+.*\s+-e|bash\s+-i                     │
│                                                                 │
│  [LDAP Injection]                                               │
│  ├── Filter Break:   \)\s*\(?\s*(?:\||&|\!)?                    │
│  ├── Wildcard:       \*\)\s*\(?\s*\w+=                          │
│  └── Null Byte:      %00|\x00                                   │
│                                                                 │
│  [SSTI]                                                         │
│  ├── Template Syntax: \{\{.*\}\}|\$\{.*\}|<%.*%>                │
│  ├── Object Access:  \.__class__|\.mro\(|\.subclasses\(         │
│  └── Code Exec:      __import__|exec\(|eval\(                   │
│                                                                 │
│  [Path Traversal]                                               │
│  ├── Directory:      \.\.[\\/]+                                 │
│  ├── Encoded:        %2e%2e[\\/]|%252e%252e                     │
│  └── Null Byte LFI:  %00\.(?:php|asp|jsp)                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Các vướng mắc

1. **False Positive risk:**
   - Generalized patterns có thể match legitimate traffic
   - Cần test kỹ với real-world data
   - Có thể cần whitelist cho một số patterns

2. **Performance:**
   - Regex phức tạp có thể ảnh hưởng latency
   - Cần benchmark so với original rules
   - Trade-off giữa coverage và speed

3. **Testing coverage:**
   - GoTestWAF có giới hạn về số payloads
   - Cần bổ sung payloads từ các nguồn khác (SQLMap, XSSHunter, etc.)
   - Cần test cross-attack scenarios

4. **Encoding edge cases:**
   - Triple/Quadruple encoding
   - Unicode normalization issues
   - Mixed encoding across different locations

5. **Priority ordering:**
   - Xác định thứ tự ưu tiên khi develop
   - XSS (44.7%) → SQLi (9.8%) → NoSQLi (10.2%) → Others

---

## 4. Tiến Độ Hiện Tại

### 4.1 Đã hoàn thành

- [x] Nghiên cứu OWASP Top 10 (2021 & 2025) - Injection category
- [x] Phân tích GoTestWAF payloads cho tất cả Injection types
- [x] Đọc và hiểu paper của nhóm nghiên cứu
- [x] Phát triển Generalized XSS Rules (8 layers, 25+ rules) - **Prototype**
- [x] Thiết kế framework cho các Injection types khác

### 4.2 Đang thực hiện

- [ ] Mở rộng Generalized approach cho SQL Injection
- [ ] Mở rộng Generalized approach cho NoSQL Injection
- [ ] Testing với GoTestWAF

### 4.3 Chưa thực hiện

- [ ] Generalized rules cho Command Injection
- [ ] Generalized rules cho LDAP/SSTI/SSI
- [ ] Generalized rules cho Path Traversal
- [ ] So sánh kết quả với rules của nhóm (toàn bộ Injection types)
- [ ] Đánh giá False Positive rate
- [ ] Viết báo cáo kết quả

---

## 5. Kế Hoạch Tiếp Theo

| Tuần | Công việc |
|------|-----------|
| 1-2 | Setup môi trường, hoàn thiện XSS Generalized |
| 3-4 | Phát triển SQLi + NoSQLi Generalized rules |
| 5-6 | Phát triển Command Injection + LDAP rules |
| 7-8 | Phát triển SSTI + SSI + Path Traversal rules |
| 9-10 | Integration testing, fix bypass cases |
| 11-12 | So sánh với Enumeration approach, đánh giá FP |
| 13-14 | Optimize, viết báo cáo cuối cùng |

---

## 6. Tổng Kết So Sánh

```
┌─────────────────────────────────────────────────────────────────┐
│                    SO SÁNH HAI PHƯƠNG PHÁP                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  NHÓM NGHIÊN CỨU (Enumeration)                                  │
│  ├── Phạm vi: 11+ Injection types         ✓                    │
│  ├── Phương pháp: Liệt kê patterns        ✓                    │
│  ├── Số rules: 146 (12 files)             ✓                    │
│  ├── Kết quả: 97.5% detection             ✓                    │
│  └── Hạn chế: Khó maintain, không auto-detect variants         │
│                                                                 │
│  ĐỀ XUẤT CỦA EM (Generalized)                                   │
│  ├── Phạm vi: 11+ Injection types         ✓ (mở rộng từ XSS)   │
│  ├── Phương pháp: Pattern tổng quát       ✓                    │
│  ├── Cấu trúc: Layered framework          ✓                    │
│  ├── Mục tiêu: ≥97.5% detection           (đang test)          │
│  └── Ưu điểm: Auto-detect variants, dễ maintain                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

*Báo cáo tiến độ - Cập nhật 02/02/2026*
