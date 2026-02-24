# Tổng Quan Đề Tài Nghiên Cứu WAF

**Sinh viên:** Quân  
**Ngày:** 25/01/2026

---

## 1. State of the Art - Hiện Trạng (GoTestWAF)

### 1.1 GoTestWAF là gì?
**GoTestWAF** là công cụ kiểm thử WAF (Web Application Firewall) tự động, gửi các payloads độc hại và hợp lệ để đánh giá khả năng phát hiện của WAF.

### 1.2 Kết quả kiểm thử OWASP CRS hiện tại

| Metric | Giá trị |
|--------|---------|
| Tổng số payloads test | 810 |
| Payloads độc hại | 669 |
| Payloads hợp lệ (False Positive test) | 141 |
| **Tỷ lệ phát hiện với encoded payloads** | **~60%** |
| **Số bypass thành công** | **264 payloads** |

### 1.3 Vấn đề chính của OWASP CRS

> [!WARNING]
> OWASP CRS chỉ phát hiện được **60%** các tấn công sử dụng encoding bypass techniques.

**Phân bố các bypass theo loại tấn công:**

| Loại Tấn Công | Số Bypass | Tỷ lệ |
|---------------|-----------|-------|
| **XSS** | 118 | 44.7% |
| NoSQL Injection | 27 | 10.2% |
| SQL Injection | 26 | 9.8% |
| LDAP Injection | 16 | 6.1% |
| SSI | 13 | 4.9% |
| SSTI | 12 | 4.5% |
| Mail/Shell/Path... | ~52 | 19.8% |

**Kỹ thuật encoding gây bypass:**
- **Base64 encoding**: 221/264 bypass (84%)
- **URL encoding**: 28/264 bypass
- **Plain text**: 15/264 bypass

---

## 2. Giải Pháp Nhóm Nghiên Cứu - TỔNG THỂ CHO TẤT CẢ ATTACK TYPES

> **Nguồn:** Paper "Computers & Security 160 (2026) 104714"

### 2.1 Phạm vi giải pháp

Nhóm nghiên cứu đã phát triển **146 custom rules** bao phủ **TẤT CẢ các loại tấn công**:

```
📁 rules/
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-XSS.conf          ← XSS (enumeration)
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-SQL-INJECTION.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-NOSQL-INJECTION.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-LDAP-INJECTION.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-SHELL-INJECTION.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-SST-INJECTION.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-SS-INCLUDE.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-PATH-TRAVERSAL.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-MAIL-INJECTION.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-RCE.conf
├── REQUEST-941-APPLICATION-CUSTOM-ATTACK-RCE-URLPATH.conf
└── REQUEST-941-APPLICATION-CUSTOM-ATTACK-COM-UA.conf
```

### 2.2 Kết quả đạt được (TOÀN BỘ ATTACK TYPES)

| Metric | Trước custom rules | Sau custom rules |
|--------|-------------------|------------------|
| Detection rate | 63% | **97.5%** |
| Bypass còn lại | 264 | **17** |
| False Positives | 141 | **141** (không tăng) |

### 2.3 Chi tiết kết quả theo từng loại tấn công

| Attack Type | Bypass trước | Bypass sau | Giảm |
|-------------|--------------|------------|------|
| **XSS** | 118 | 11 | **90.7%** |
| NoSQL Injection | 27 | 0 | **100%** |
| SQL Injection | 26 | 2 | **92.3%** |
| LDAP Injection | 16 | 0 | **100%** |
| SSI | 13 | 1 | **92.3%** |
| SSTI | 12 | 0 | **100%** |
| Path Traversal | 11 | 1 | **90.9%** |
| Shell Injection | 11 | 0 | **100%** |

### 2.4 Các kỹ thuật chính của nhóm

1. **Multiple encoding handling** - Xử lý Base64 + URL encoding kết hợp
2. **URLPath decoding** - Giải mã payload sau slash cuối cùng
3. **Targeted decoding** - Giải mã component cụ thể (không dùng auto-decoding)
4. **Enumeration-based patterns** - Liệt kê từng pattern cụ thể cho mỗi loại tấn công

---

## 3. Giải Pháp Của Em - GENERALIZED XSS DETECTION

### 3.1 Phạm vi và mục tiêu

> [!IMPORTANT]
> Em tập trung phát triển giải pháp **CHỈ CHO XSS** nhưng với phương pháp **KHÁC BIỆT** so với nhóm.

| Tiêu chí | Nhóm nghiên cứu | Em |
|----------|-----------------|-----|
| **Phạm vi** | Tất cả attack types | **Chỉ XSS** |
| **Phương pháp** | Enumeration (liệt kê) | **Generalized (tổng quát)** |
| **File** | `*-CUSTOM-ATTACK-XSS.conf` | `*-XSS-GENERALIZED.conf` |
| **Size** | 5,331 bytes | **40,606 bytes** |
| **Cấu trúc** | Flat rules | **8 Layers** |

### 3.2 Tại sao chọn XSS?

```
┌────────────────────────────────────────────────────────────────┐
│  XSS chiếm 44.7% (118/264) tổng số bypass                      │
│  → Là loại tấn công có nhiều bypass nhất                       │
│  → Sau khi nhóm fix, vẫn còn 11 bypass (nhiều nhất)            │
│  → Cần giải pháp mạnh hơn để xử lý triệt để                    │
└────────────────────────────────────────────────────────────────┘
```

### 3.3 So sánh 2 phương pháp detection

| Enumeration-based (Nhóm) | Generalized (Em) |
|--------------------------|------------------|
| Liệt kê: `<script>`, `<svg>`, `<img>`... | Pattern: `<\s*(?:script\|svg\|img...)` |
| Liệt kê: `onclick`, `onerror`, `onload`... | Pattern: `on\w+\s*=` |
| Cần update khi có tag/event mới | Tự động bắt tag/event mới |
| Dễ bị bypass bằng biến thể | Bắt được biến thể |

### 3.4 Kiến trúc 8 Layers đã phát triển

```
┌─────────────────────────────────────────────────────────────────┐
│                     XSS GENERALIZED DETECTION                    │
├─────────────────────────────────────────────────────────────────┤
│  Layer 0: URL Path Capture & Decode                             │
│  Layer 1: ARGS_GET (URL Parameters)                             │
│  Layer 2: ARGS (POST/JSON Data)                                 │
│  Layer 3: REQUEST_HEADERS                                       │
│  Layer 4: Nested Base64 Detection                               │
│  Layer 5: Mixed Encoding (URL↔Base64)                           │
│  Layer 6: REQUEST_URI Path Detection                            │
│  Layer 7: Special Bypass Patterns                               │
│  Layer 8: Additional Bypass Fixes                               │
└─────────────────────────────────────────────────────────────────┘
```

### 3.5 Các pattern detection chính

| Pattern | Mục đích | Ví dụ bắt được |
|---------|----------|----------------|
| `<\s*(?:script\|svg...)` | HTML Tags | `<script>`, `< svg>`, `<ScRiPt>` |
| `on\w+\s*=` | Event handlers | `onclick=`, `ONERROR=`, `onXXX=` |
| `(?:alert\|confirm\|prompt)\s*[\(\`]` | JS Functions | `alert(1)`, `confirm\`1\`` |
| `['"]\s*\+\s*['"]` | String concat | `'ale'+'rt(1)'` |
| `\.(?:call\|apply\|bind)\s*\(` | Function invoke | `alert.call(null,1)` |
| `constructor\s*[\(\`]` | Prototype pollution | `[].constructor('...')` |

### 3.6 Tiến độ hiện tại

- [x] Phân tích GoTestWAF payloads và mapping với OWASP Top 10
- [x] Nghiên cứu paper của nhóm về encoding bypass
- [x] **Phát triển Generalized XSS Rules (8 layers, 25+ rules)**
- [ ] Testing và so sánh hiệu quả với rules của nhóm
- [ ] Đánh giá False Positive rate

---

## 4. Tổng Kết So Sánh

```
┌─────────────────────────────────────────────────────────────────┐
│                        SO SÁNH GIẢI PHÁP                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  NHÓM NGHIÊN CỨU (146 rules)                                   │
│  ├── XSS (enumeration)          ✓                              │
│  ├── SQL Injection              ✓                              │
│  ├── NoSQL Injection            ✓                              │
│  ├── LDAP Injection             ✓                              │
│  ├── Shell Injection            ✓                              │
│  ├── SSTI                       ✓                              │
│  ├── SSI                        ✓                              │
│  ├── Path Traversal             ✓                              │
│  ├── Mail Injection             ✓                              │
│  └── RCE                        ✓                              │
│                                                                 │
│  EM (25+ rules) - CHỈ XSS NHƯNG GENERALIZED                    │
│  └── XSS (generalized, 8 layers) ✓✓✓                           │
│      └── Mục tiêu: Fix 11 bypass còn lại + future-proof        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tài Liệu Tham Khảo

1. OWASP Top 10:2025 - https://owasp.org/Top10/2025/
2. OWASP Top 10:2021 - https://owasp.org/Top10/2021/
3. Research Paper: "Computers & Security 160 (2026) 104714"
4. GoTestWAF: https://github.com/wallarm/gotestwaf

---

*Tài liệu tổng quan cho báo cáo tiến độ - Cập nhật 25/01/2026*
