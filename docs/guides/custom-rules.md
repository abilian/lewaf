# Custom WAF Rules Guide

This guide teaches you how to write effective custom WAF rules for LeWAF. You'll learn SecLang rule syntax, understand rule evaluation phases, and discover patterns for common security scenarios.

## Table of Contents

1. [Introduction](#introduction)
2. [Rule Syntax Basics](#rule-syntax-basics)
3. [Variables](#variables)
4. [Operators](#operators)
5. [Transformations](#transformations)
6. [Actions](#actions)
7. [Rule Phases](#rule-phases)
8. [Writing Effective Rules](#writing-effective-rules)
9. [Testing Custom Rules](#testing-custom-rules)
10. [Common Patterns](#common-patterns)
11. [Performance Optimization](#performance-optimization)
12. [Debugging Rules](#debugging-rules)

---

## Introduction

### What Are Custom Rules?

Custom WAF rules allow you to define application-specific security policies beyond generic protections. They let you:

- **Block specific attack patterns** targeting your application
- **Enforce business logic** (rate limiting, input validation)
- **Protect sensitive endpoints** (admin panels, API keys)
- **Implement compliance requirements** (PCI-DSS, GDPR)

### When to Write Custom Rules

Write custom rules when:

- ✅ Generic rules create false positives for your app
- ✅ You need application-specific protections
- ✅ Compliance requires specific controls
- ✅ You discover attack patterns targeting your app

Don't write custom rules for:

- ❌ Common attacks (use OWASP CRS instead)
- ❌ Generic protections (start with defaults)
- ❌ Prematurely optimizing security

### Rule Philosophy

Good rules are:

- **Specific**: Target known threats, not hypothetical ones
- **Fast**: Minimal performance impact
- **Testable**: Can verify they work correctly
- **Maintainable**: Well-documented and versioned

---

## Rule Syntax Basics

### Anatomy of a Rule

Every SecLang rule follows this structure:

```
SecRule VARIABLES "OPERATOR" "ACTIONS"
```

**Example**:
```apache
SecRule ARGS "@rx <script" "id:1,phase:2,deny,log,msg:'XSS Attack'"
```

**Breaking it down**:
- `SecRule` - Rule directive
- `ARGS` - Variable to inspect (request parameters)
- `"@rx <script"` - Operator with pattern (regex match for `<script`)
- `"id:1,phase:2,deny,log,msg:'XSS Attack'"` - Actions to take

### Minimal Valid Rule

The simplest possible rule:

```apache
SecRule ARGS "@rx attack" "id:1,phase:2,deny"
```

**Required components**:
- `id` - Unique numeric identifier
- `phase` - When to evaluate (1-5)
- Action - What to do if matched (`deny`, `log`, `pass`, etc.)

### Rule Chaining

Chain multiple conditions together (all must match):

```apache
SecRule REQUEST_METHOD "@streq POST" "id:1,phase:2,chain"
SecRule REQUEST_URI "@rx /admin" "deny,log,msg:'Admin POST blocked'"
```

Both conditions must be true for the rule to trigger.

---

## Variables

Variables define **what to inspect** in the request/response.

### Request Variables

#### ARGS - Request Parameters

Inspects all query string and POST parameters:

```apache
# Block any parameter containing "admin"
SecRule ARGS "@contains admin" "id:100,phase:2,deny"
```

**Example matches**:
- `?username=admin` ✅
- `?role=administrator` ✅
- `POST user=admin` ✅

#### ARGS_NAMES - Parameter Names

Inspects parameter names, not values:

```apache
# Block parameters named "debug" or "test"
SecRule ARGS_NAMES "@rx ^(debug|test)$" "id:101,phase:2,deny"
```

**Example matches**:
- `?debug=1` ✅
- `?test=true` ✅
- `?prod=false` ❌

#### REQUEST_URI - Request Path

Inspects the URL path:

```apache
# Block path traversal attempts
SecRule REQUEST_URI "@rx \\.\\./|\\.\\.\\\\". "id:102,phase:1,deny"
```

**Example matches**:
- `/../../etc/passwd` ✅
- `/admin/../config.php` ✅
- `/normal/path` ❌

#### REQUEST_METHOD - HTTP Method

Inspects the HTTP method:

```apache
# Only allow GET and POST
SecRule REQUEST_METHOD "!@rx ^(GET|POST)$" "id:103,phase:1,deny"
```

**Example matches**:
- `DELETE /users/1` ✅ (blocked)
- `PUT /items/5` ✅ (blocked)
- `GET /items` ❌ (allowed)

#### REQUEST_HEADERS - Request Headers

Inspects all request headers:

```apache
# Block requests without User-Agent
SecRule REQUEST_HEADERS:User-Agent "^$" "id:104,phase:1,deny"
```

**Specific header**:
```apache
# Require authentication header
SecRule REQUEST_HEADERS:Authorization "^$" "id:105,phase:1,deny,msg:'Missing auth'"
```

#### REQUEST_BODY - Request Body

Inspects POST/PUT request body:

```apache
# Block JSON containing "malicious"
SecRule REQUEST_BODY "@contains malicious" "id:106,phase:2,deny"
```

**Note**: Only available in phase 2+ (after body is read).

#### REMOTE_ADDR - Client IP Address

Inspects the client's IP:

```apache
# Block specific IP range
SecRule REMOTE_ADDR "@ipMatch 192.168.1.0/24" "id:107,phase:1,deny"
```

### Response Variables

#### RESPONSE_STATUS - HTTP Status Code

Inspects the response status:

```apache
# Log all 500 errors
SecRule RESPONSE_STATUS "@rx ^5" "id:200,phase:4,log,msg:'Server error'"
```

#### RESPONSE_HEADERS - Response Headers

Inspects response headers:

```apache
# Ensure security headers are set
SecRule RESPONSE_HEADERS:X-Frame-Options "^$" "id:201,phase:3,log,msg:'Missing X-Frame-Options'"
```

#### RESPONSE_BODY - Response Body

Inspects response body (use cautiously - performance impact):

```apache
# Detect SQL errors in response
SecRule RESPONSE_BODY "@rx SQL syntax error" "id:202,phase:4,log,msg:'SQL error leaked'"
```

### Variable Selectors

Use colons to select specific items:

```apache
# Specific parameter
SecRule ARGS:username "@rx admin" "id:300,phase:2,deny"

# Specific header
SecRule REQUEST_HEADERS:Cookie "@contains sessionid" "id:301,phase:1,log"
```

### Variable Collections

Combine multiple variables with pipe `|`:

```apache
# Inspect both args and body
SecRule ARGS|REQUEST_BODY "@rx <script" "id:400,phase:2,deny"

# Inspect all user-controlled input
SecRule ARGS|ARGS_NAMES|REQUEST_HEADERS|REQUEST_BODY "@rx attack" "id:401,phase:2,deny"
```

---

## Operators

Operators define **how to match** the variable value.

### String Operators

#### @streq - String Equals (Case-Sensitive)

Exact match:

```apache
# Only block exact string "admin"
SecRule ARGS:role "@streq admin" "id:500,phase:2,deny"
```

**Matches**: `?role=admin` ✅
**Doesn't match**: `?role=Admin` ❌, `?role=administrator` ❌

#### @contains - Contains Substring

Substring match:

```apache
# Block if contains "script"
SecRule ARGS "@contains script" "id:501,phase:2,deny"
```

**Matches**: `?q=<script>`, `?q=javascript:alert`, `?q=myscript.js` ✅

#### @beginsWith / @endsWith - Prefix/Suffix Match

```apache
# Block parameters starting with "__"
SecRule ARGS_NAMES "@beginsWith __" "id:502,phase:2,deny"

# Block files ending with .exe
SecRule ARGS:filename "@endsWith .exe" "id:503,phase:2,deny"
```

### Regex Operators

#### @rx - Regular Expression

Most powerful operator for pattern matching:

```apache
# XSS patterns
SecRule ARGS "@rx <script[^>]*>.*?</script>" "id:600,phase:2,deny"

# SQL injection patterns
SecRule ARGS "@rx (?i:union.*select|insert.*into)" "id:601,phase:2,deny"

# Email validation
SecRule ARGS:email "@rx ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" "id:602,phase:2,pass"
```

**Regex flags**:
- `(?i:...)` - Case-insensitive
- `(?:...)` - Non-capturing group
- `.*?` - Non-greedy match

**Performance tip**: Anchor regex when possible (`^`, `$`) to fail fast.

#### @pm - Phrase Match (Fast String Search)

Matches any of multiple strings efficiently:

```apache
# Block common SQL keywords (faster than regex)
SecRule ARGS "@pm union select insert delete drop" "id:610,phase:2,deny"
```

**Use when**:
- Matching multiple exact strings
- Performance is critical
- Don't need pattern flexibility

### Numeric Operators

#### @gt / @lt / @eq - Greater Than / Less Than / Equals

```apache
# Block large requests (> 1MB)
SecRule REQUEST_BODY "@gt 1048576" "id:700,phase:2,deny,msg:'Request too large'"

# Block negative user IDs
SecRule ARGS:user_id "@lt 0" "id:701,phase:2,deny,msg:'Invalid user ID'"

# Require specific version
SecRule REQUEST_HEADERS:API-Version "@eq 2" "id:702,phase:1,deny,msg:'API v2 required'"
```

### IP Operators

#### @ipMatch - IP Address/Range Match

```apache
# Block IP range
SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" "id:800,phase:1,deny"

# Allow only specific IPs
SecRule REMOTE_ADDR "!@ipMatch 192.168.1.100,192.168.1.101" "id:801,phase:1,deny"
```

### File Operators

#### @validateByteRange - Character Whitelist

Ensures input only contains allowed characters:

```apache
# Only allow alphanumeric + basic punctuation
SecRule ARGS "@validateByteRange 32-126" "id:900,phase:2,deny,msg:'Invalid characters'"
```

**Byte ranges**:
- `32-126` - Printable ASCII
- `48-57` - Digits (0-9)
- `65-90` - Uppercase letters (A-Z)
- `97-122` - Lowercase letters (a-z)

### Negation

Negate any operator with `!`:

```apache
# Block if NOT a valid email
SecRule ARGS:email "!@rx ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" "id:1000,phase:2,deny"

# Block non-GET requests
SecRule REQUEST_METHOD "!@streq GET" "id:1001,phase:1,deny"
```

---

## Transformations

Transformations **normalize data** before operators run.

### Why Transformations?

Attackers use encoding to bypass filters:

```
Original:    <script>alert(1)</script>
URL encoded: %3Cscript%3Ealert(1)%3C%2Fscript%3E
HTML entity: &lt;script&gt;alert(1)&lt;/script&gt;
Uppercase:   <SCRIPT>ALERT(1)</SCRIPT>
```

Transformations decode and normalize input to catch evasion attempts.

### Common Transformations

#### t:lowercase - Convert to Lowercase

```apache
# Case-insensitive matching
SecRule ARGS "@rx <script" "id:1100,phase:2,deny,t:lowercase"
```

**Before**: `<SCRIPT>`, `<ScRiPt>`, `<script>`
**After**: `<script>`, `<script>`, `<script>`
**Result**: All match ✅

#### t:urlDecode - URL Decode

```apache
# Decode URL-encoded attacks
SecRule ARGS "@rx <script" "id:1101,phase:2,deny,t:urlDecode,t:lowercase"
```

**Before**: `%3Cscript%3E`
**After URL decode**: `<script>`
**After lowercase**: `<script>`
**Result**: Matches ✅

#### t:htmlEntityDecode - Decode HTML Entities

```apache
# Decode HTML entity attacks
SecRule ARGS "@rx <script" "id:1102,phase:2,deny,t:htmlEntityDecode,t:lowercase"
```

**Before**: `&lt;script&gt;`
**After decode**: `<script>`
**Result**: Matches ✅

#### t:base64Decode - Base64 Decode

```apache
# Detect base64-encoded payloads
SecRule ARGS "@rx <script" "id:1103,phase:2,deny,t:base64Decode,t:lowercase"
```

**Before**: `PHNjcmlwdD4=` (base64 for `<script>`)
**After decode**: `<script>`
**Result**: Matches ✅

#### t:removeWhitespace - Remove All Whitespace

```apache
# Detect whitespace evasion
SecRule ARGS "@rx <script>" "id:1104,phase:2,deny,t:removeWhitespace,t:lowercase"
```

**Before**: `< script >`, `<\nscript\n>`
**After**: `<script>`
**Result**: Matches ✅

#### t:normalizePath - Normalize Paths

```apache
# Detect path traversal after normalization
SecRule REQUEST_URI "@contains /etc/passwd" "id:1105,phase:1,deny,t:normalizePath"
```

**Before**: `/foo/../bar/../../etc/passwd`
**After**: `/etc/passwd`
**Result**: Matches ✅

### Transformation Chains

Apply multiple transformations in order:

```apache
# Comprehensive XSS detection
SecRule ARGS "@rx <script" \
  "id:1200,phase:2,deny,\
  t:urlDecode,\
  t:htmlEntityDecode,\
  t:lowercase,\
  t:removeWhitespace"
```

**Order matters**:
1. URL decode first (handles `%3C`)
2. HTML entity decode (handles `&lt;`)
3. Lowercase (handles `<SCRIPT>`)
4. Remove whitespace (handles `< script >`)

---

## Actions

Actions define **what happens** when a rule matches.

### Disruptive Actions

#### deny - Block Request

```apache
# Block and return 403
SecRule ARGS "@rx attack" "id:1300,phase:2,deny"
```

**Result**: Returns 403 Forbidden, stops processing.

#### drop - Drop Connection

```apache
# Silently drop connection
SecRule ARGS "@rx scan" "id:1301,phase:2,drop"
```

**Result**: Connection closed immediately, no response sent.

#### pass - Allow Request

```apache
# Explicitly allow (useful with chaining)
SecRule ARGS:token "@rx ^[a-f0-9]{32}$" "id:1302,phase:2,pass"
```

**Result**: Continue processing request.

#### redirect - Redirect to URL

```apache
# Redirect to error page
SecRule ARGS "@rx badword" "id:1303,phase:2,redirect:https://example.com/error"
```

**Result**: Returns 302 redirect.

### Non-Disruptive Actions

#### log - Log Match

```apache
# Log but don't block
SecRule RESPONSE_STATUS "@rx ^5" "id:1400,phase:4,log,msg:'Server error detected'"
```

**Result**: Writes to log, continues processing.

#### msg - Log Message

```apache
SecRule ARGS "@rx attack" "id:1401,phase:2,deny,log,msg:'XSS attack detected in parameter'"
```

**Result**: Custom message in logs.

#### tag - Add Tag

```apache
SecRule ARGS "@rx <script" "id:1402,phase:2,deny,tag:'OWASP_CRS/WEB_ATTACK/XSS'"
```

**Result**: Tags event for categorization.

#### severity - Set Severity Level

```apache
SecRule ARGS "@rx union.*select" "id:1403,phase:2,deny,severity:CRITICAL,msg:'SQL injection'"
```

**Severity levels**: EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG

#### status - Set HTTP Status Code

```apache
# Return custom status code
SecRule ARGS "@rx badword" "id:1404,phase:2,deny,status:406,msg:'Not acceptable'"
```

**Result**: Returns HTTP 406 instead of default 403.

### Flow Control Actions

#### chain - Chain Rules

```apache
# Both conditions must match
SecRule REQUEST_METHOD "@streq POST" "id:1500,phase:2,chain"
SecRule REQUEST_URI "@rx /admin" "deny,log,msg:'Admin POST blocked'"
```

#### skip - Skip Next N Rules

```apache
# If safe, skip blocking rules
SecRule ARGS:safe_mode "@eq 1" "id:1501,phase:2,skip:2"
SecRule ARGS "@rx attack" "id:1502,phase:2,deny"
SecRule ARGS "@rx malware" "id:1503,phase:2,deny"
```

#### skipAfter - Jump to Marker

```apache
SecRule REQUEST_URI "@rx ^/public" "id:1510,phase:1,skipAfter:END_PUBLIC_CHECKS"
SecRule ARGS "@rx attack" "id:1511,phase:2,deny"
SecMarker END_PUBLIC_CHECKS
```

---

## Rule Phases

Phases determine **when** rules execute in the request/response lifecycle.

### Phase 1: Request Headers

**When**: After request headers received, before body read
**Available variables**: REQUEST_URI, REQUEST_METHOD, REQUEST_HEADERS, REMOTE_ADDR
**Use for**: Fast checks on headers, early blocking, rate limiting

```apache
# Block based on User-Agent (phase 1 - fastest)
SecRule REQUEST_HEADERS:User-Agent "@rx BadBot" "id:2000,phase:1,deny"

# Block path traversal early
SecRule REQUEST_URI "@rx \\.\\." "id:2001,phase:1,deny"

# Rate limit by IP
SecRule REMOTE_ADDR "@ipMatch 192.168.1.100" "id:2002,phase:1,deny"
```

**Advantages**:
- ⚡ Fastest (no body read required)
- 💾 Saves bandwidth (blocks before receiving body)
- 🎯 Best for header-based rules

### Phase 2: Request Body

**When**: After request body received
**Available variables**: All request variables including ARGS, REQUEST_BODY
**Use for**: Parameter inspection, POST data validation, file uploads

```apache
# Check POST parameters (needs phase 2)
SecRule ARGS "@rx <script" "id:2100,phase:2,deny"

# Validate JSON body
SecRule REQUEST_BODY "@rx \\{.*password.*\\}" "id:2101,phase:2,log"

# Check file upload names
SecRule FILES_NAMES "@rx \\.php$" "id:2102,phase:2,deny"
```

**Advantages**:
- 📄 Full request available
- 🔍 Can inspect body content
- 🎯 Best for input validation

**Disadvantage**:
- ⏱️ Slower (must read full body)

### Phase 3: Response Headers

**When**: After backend processes request, before response body sent
**Available variables**: RESPONSE_STATUS, RESPONSE_HEADERS
**Use for**: Response header validation, security headers enforcement

```apache
# Ensure security headers
SecRule RESPONSE_HEADERS:X-Frame-Options "^$" "id:2200,phase:3,log,msg:'Missing X-Frame-Options'"

# Block error status codes
SecRule RESPONSE_STATUS "@rx ^5" "id:2201,phase:3,log,msg:'Server error'"

# Add custom header on suspicious requests
SecRule ARGS "@rx admin" "id:2202,phase:3,pass,setenv:suspicious=1"
```

### Phase 4: Response Body

**When**: After response body generated
**Available variables**: RESPONSE_BODY
**Use for**: Data leak prevention, sensitive info detection

```apache
# Detect credit card numbers in response
SecRule RESPONSE_BODY "@rx \b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b" \
  "id:2300,phase:4,log,msg:'Potential credit card leak'"

# Detect SQL errors leaked to client
SecRule RESPONSE_BODY "@rx (SQL syntax|mysql_fetch|ORA-\d+)" \
  "id:2301,phase:4,log,msg:'SQL error leaked'"

# Detect AWS keys in response
SecRule RESPONSE_BODY "@rx AKIA[0-9A-Z]{16}" \
  "id:2302,phase:4,log,msg:'AWS key detected in response'"
```

**Warning**: Inspecting response bodies has performance impact. Use sparingly.

### Phase 5: Logging

**When**: After response sent
**Available variables**: All variables
**Use for**: Audit logging, analytics, post-processing

```apache
# Log all admin access
SecRule REQUEST_URI "@rx ^/admin" "id:2400,phase:5,log,msg:'Admin access logged'"

# Aggregate transaction data
SecRule TX:SCORE "@gt 10" "id:2401,phase:5,log,msg:'High threat score'"
```

### Choosing the Right Phase

| Check Type | Best Phase | Reason |
|------------|------------|--------|
| User-Agent check | 1 | Available early, fast |
| Path traversal | 1 | Available in URI, fast |
| POST parameter validation | 2 | Needs body |
| File upload check | 2 | Needs body |
| Security headers enforcement | 3 | Response headers available |
| Data leak prevention | 4 | Needs response body |
| Audit logging | 5 | After complete transaction |

---

## Writing Effective Rules

### Rule Design Principles

#### 1. Be Specific

**Bad** (too broad):
```apache
# Blocks legitimate requests containing "script" (JavaScript files, etc.)
SecRule ARGS "@contains script" "id:3000,phase:2,deny"
```

**Good** (specific pattern):
```apache
# Only blocks actual script tags
SecRule ARGS "@rx <script[^>]*>" "id:3000,phase:2,deny"
```

#### 2. Fail Securely

**Bad** (allows bypass if regex fails):
```apache
SecRule ARGS:email "@rx ^[a-z]+@[a-z]+\.[a-z]+$" "id:3001,phase:2,pass"
```

**Good** (denies invalid input):
```apache
SecRule ARGS:email "!@rx ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" \
  "id:3001,phase:2,deny,msg:'Invalid email format'"
```

#### 3. Use Appropriate Operators

**Bad** (slow regex for exact match):
```apache
SecRule REQUEST_METHOD "@rx ^POST$" "id:3002,phase:1,deny"
```

**Good** (fast string comparison):
```apache
SecRule REQUEST_METHOD "@streq POST" "id:3002,phase:1,deny"
```

**Bad** (regex for multiple strings):
```apache
SecRule ARGS "@rx (union|select|insert|delete)" "id:3003,phase:2,deny"
```

**Good** (phrase match is faster):
```apache
SecRule ARGS "@pm union select insert delete" "id:3003,phase:2,deny"
```

#### 4. Apply Transformations

**Bad** (misses encoded attacks):
```apache
SecRule ARGS "@rx <script" "id:3004,phase:2,deny"
```

**Good** (handles encoding):
```apache
SecRule ARGS "@rx <script" "id:3004,phase:2,deny,t:urlDecode,t:htmlEntityDecode,t:lowercase"
```

#### 5. Document Your Rules

```apache
# Rule ID: 3005
# Purpose: Block SQL injection in search parameter
# Added: 2024-01-15
# Author: Security Team
# OWASP: A03:2021 - Injection
# False Positives: None known
# Test: curl "http://test/?q=' OR '1'='1"
SecRule ARGS:q "@rx (?i:union.*select|'.*or.*')" \
  "id:3005,phase:2,deny,log,\
  msg:'SQL injection in search',\
  tag:'OWASP_A03',\
  severity:CRITICAL"
```

### Common Mistakes

#### Mistake 1: Overly Broad Patterns

```apache
# BAD: Blocks "admin" everywhere (including emails like "admin@example.com")
SecRule REQUEST_BODY "@contains admin" "id:3100,phase:2,deny"

# GOOD: Only block admin in specific parameter
SecRule ARGS:username "@streq admin" "id:3100,phase:2,deny"
```

#### Mistake 2: Not Handling Encoding

```apache
# BAD: Misses URL-encoded attacks
SecRule ARGS "@contains <script>" "id:3101,phase:2,deny"

# GOOD: Decodes before checking
SecRule ARGS "@contains <script>" "id:3101,phase:2,deny,t:urlDecode"
```

#### Mistake 3: Inefficient Regex

```apache
# BAD: Catastrophic backtracking possible
SecRule ARGS "@rx (a+)+(b+)+" "id:3102,phase:2,deny"

# GOOD: Specific, bounded pattern
SecRule ARGS "@rx ^[ab]{1,100}$" "id:3102,phase:2,deny"
```

#### Mistake 4: Wrong Phase

```apache
# BAD: Phase 1 doesn't have ARGS available
SecRule ARGS "@rx attack" "id:3103,phase:1,deny"

# GOOD: Use phase 2 for request body/params
SecRule ARGS "@rx attack" "id:3103,phase:2,deny"
```

---

## Testing Custom Rules

### Unit Testing Rules

**Test file** (`tests/test_custom_rules.py`):

```python
import pytest
from httpx import AsyncClient
from your_app import protected_app

@pytest.mark.asyncio
async def test_xss_rule_blocks_script_tags():
    """Test that XSS rule blocks <script> tags"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        response = await client.get("/?q=<script>alert(1)</script>")
        assert response.status_code == 403

@pytest.mark.asyncio
async def test_xss_rule_allows_safe_input():
    """Test that XSS rule allows safe input"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        response = await client.get("/?q=python")
        assert response.status_code == 200

@pytest.mark.asyncio
async def test_xss_rule_blocks_encoded_attacks():
    """Test that XSS rule blocks URL-encoded attacks"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        # URL-encoded <script>
        response = await client.get("/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        assert response.status_code == 403

@pytest.mark.asyncio
async def test_xss_rule_blocks_mixed_case():
    """Test that XSS rule blocks mixed-case evasion"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        response = await client.get("/?q=<ScRiPt>alert(1)</sCrIpT>")
        assert response.status_code == 403
```

### Integration Testing

**Test realistic attack scenarios**:

```python
@pytest.mark.asyncio
async def test_sql_injection_in_login():
    """Test SQL injection protection in login form"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        # Attempt SQL injection
        response = await client.post(
            "/login",
            json={
                "username": "admin' OR '1'='1",
                "password": "password"
            }
        )
        assert response.status_code == 403

@pytest.mark.asyncio
async def test_path_traversal_in_file_access():
    """Test path traversal protection"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        # Attempt path traversal
        response = await client.get("/files?path=../../etc/passwd")
        assert response.status_code == 403

        # Safe file access should work
        response = await client.get("/files?path=documents/report.pdf")
        assert response.status_code in [200, 404]  # Either exists or not, but not blocked
```

### False Positive Testing

**Ensure legitimate requests aren't blocked**:

```python
@pytest.mark.asyncio
async def test_legitimate_admin_email():
    """Test that admin emails aren't blocked"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        # Should NOT block legitimate email
        response = await client.post(
            "/contact",
            json={"email": "admin@example.com", "message": "Hello"}
        )
        assert response.status_code == 200

@pytest.mark.asyncio
async def test_legitimate_javascript_discussion():
    """Test that discussions about JavaScript aren't blocked"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        # Should NOT block the word "script" in normal context
        response = await client.post(
            "/forum/post",
            json={"title": "JavaScript best practices", "body": "I wrote a script..."}
        )
        assert response.status_code == 200
```

### Load Testing

**Test performance impact**:

```python
import time

@pytest.mark.asyncio
async def test_rule_performance():
    """Test that rules don't significantly impact performance"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        # Baseline: without attack patterns
        start = time.time()
        for _ in range(100):
            response = await client.get("/?q=test")
            assert response.status_code == 200
        baseline_duration = time.time() - start

        # With attack patterns (will be blocked)
        start = time.time()
        for _ in range(100):
            response = await client.get("/?q=<script>")
            assert response.status_code == 403
        blocked_duration = time.time() - start

        # Blocking should be fast (ideally faster than processing)
        assert blocked_duration < baseline_duration * 2  # Less than 2x overhead
```

---

## Common Patterns

### Pattern 1: API Key Validation

```apache
# Require API key in header
SecRule REQUEST_HEADERS:X-API-Key "^$" \
  "id:4000,phase:1,deny,status:401,msg:'Missing API key'"

# Validate API key format (32 hex characters)
SecRule REQUEST_HEADERS:X-API-Key "!@rx ^[a-f0-9]{32}$" \
  "id:4001,phase:1,deny,status:401,msg:'Invalid API key format'"
```

### Pattern 2: Rate Limiting by IP

```apache
# Track request count per IP (simplified - use proper rate limiting in production)
SecRule REMOTE_ADDR "@unconditionalMatch" \
  "id:4100,phase:1,pass,setvar:ip.req_count=+1"

# Block if too many requests
SecRule IP:REQ_COUNT "@gt 100" \
  "id:4101,phase:1,deny,status:429,msg:'Rate limit exceeded'"

# Reset counter every 60 seconds
SecRule REMOTE_ADDR "@unconditionalMatch" \
  "id:4102,phase:5,pass,expirevar:ip.req_count=60"
```

### Pattern 3: Admin Panel Protection

```apache
# Require authentication for /admin/*
SecRule REQUEST_URI "@beginsWith /admin" \
  "id:4200,phase:1,chain"
SecRule REQUEST_HEADERS:Cookie "!@contains admin_session=" \
  "deny,status:401,msg:'Admin authentication required'"

# Only allow specific IPs for admin
SecRule REQUEST_URI "@beginsWith /admin" \
  "id:4201,phase:1,chain"
SecRule REMOTE_ADDR "!@ipMatch 192.168.1.0/24,10.0.0.0/8" \
  "deny,status:403,msg:'Admin access denied from this IP'"

# Block dangerous operations
SecRule REQUEST_URI "@rx /admin/(delete|drop)" \
  "id:4202,phase:1,chain"
SecRule REQUEST_METHOD "!@streq POST" \
  "deny,msg:'Admin operations require POST'"
```

### Pattern 4: File Upload Security

```apache
# Limit upload size (10MB)
SecRule FILES_SIZES "@gt 10485760" \
  "id:4300,phase:2,deny,msg:'File too large (max 10MB)'"

# Block dangerous file extensions
SecRule FILES_NAMES "@rx \\.(php|exe|sh|bat|cmd|jsp|asp|aspx|dll)$" \
  "id:4301,phase:2,deny,msg:'Dangerous file type'"

# Block double extensions (e.g., image.jpg.php)
SecRule FILES_NAMES "@rx \.[^.]+\.(php|exe|sh)$" \
  "id:4302,phase:2,deny,msg:'Double extension detected'"

# Check for PHP code in uploads
SecRule FILES "@rx <\?php" \
  "id:4303,phase:2,deny,msg:'PHP code in uploaded file'"

# Require Content-Type for uploads
SecRule FILES_NAMES "@rx .+" \
  "id:4304,phase:2,chain"
SecRule REQUEST_HEADERS:Content-Type "!@contains multipart/form-data" \
  "deny,msg:'Invalid content type for file upload'"
```

### Pattern 5: GraphQL Query Protection

```apache
# Limit query depth (prevent nested query attacks)
SecRule REQUEST_BODY "@rx \\{.*\\{.*\\{.*\\{.*\\{" \
  "id:4400,phase:2,deny,msg:'GraphQL query too deep (max 4 levels)'"

# Limit query length
SecRule REQUEST_BODY "@gt 5000" \
  "id:4401,phase:2,deny,msg:'GraphQL query too long'"

# Block introspection queries in production
SecRule REQUEST_BODY "@rx __schema|__type|__typename" \
  "id:4402,phase:2,deny,msg:'GraphQL introspection blocked'"

# Prevent batch query attacks
SecRule REQUEST_BODY "@rx \\[.*query.*query.*query" \
  "id:4403,phase:2,deny,msg:'GraphQL batch queries blocked'"
```

### Pattern 6: JWT Validation

```apache
# Require JWT in Authorization header
SecRule REQUEST_HEADERS:Authorization "^$" \
  "id:4500,phase:1,deny,status:401,msg:'Missing authorization header'"

# Check JWT format (3 base64 parts)
SecRule REQUEST_HEADERS:Authorization "!@rx ^Bearer [A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$" \
  "id:4501,phase:1,deny,status:401,msg:'Invalid JWT format'"

# Block expired "none" algorithm (security vulnerability)
SecRule REQUEST_HEADERS:Authorization "@rx \\.eyJhbGciOiJub25lIg==" \
  "id:4502,phase:1,deny,status:403,msg:'JWT none algorithm blocked'"
```

### Pattern 7: Content-Type Validation

```apache
# Require Content-Type for POST/PUT
SecRule REQUEST_METHOD "@rx ^(POST|PUT|PATCH)$" \
  "id:4600,phase:1,chain"
SecRule REQUEST_HEADERS:Content-Type "^$" \
  "deny,status:400,msg:'Content-Type required'"

# Only allow specific Content-Types for API
SecRule REQUEST_URI "@beginsWith /api" \
  "id:4601,phase:1,chain"
SecRule REQUEST_HEADERS:Content-Type "!@rx ^(application/json|application/xml)$" \
  "deny,status:415,msg:'Unsupported media type'"

# Block multipart/form-data on API endpoints (force JSON)
SecRule REQUEST_URI "@beginsWith /api" \
  "id:4602,phase:1,chain"
SecRule REQUEST_HEADERS:Content-Type "@contains multipart/form-data" \
  "deny,status:415,msg:'Use application/json'"
```

---

## Performance Optimization

### Rule Optimization Strategies

#### 1. Use Early Phases

**Slow** (reads entire body unnecessarily):
```apache
SecRule ARGS:token "@eq badtoken" "id:5000,phase:2,deny"
```

**Fast** (checks header in phase 1):
```apache
SecRule REQUEST_HEADERS:X-API-Token "@eq badtoken" "id:5000,phase:1,deny"
```

#### 2. Order Rules by Likelihood

Put most common blocks first:

```apache
# Common attack (check first)
SecRule ARGS "@rx <script" "id:5001,phase:2,deny"

# Less common attack (check later)
SecRule ARGS "@rx (?i:union.*select)" "id:5002,phase:2,deny"

# Rare attack (check last)
SecRule ARGS "@rx (?i:into.*outfile)" "id:5003,phase:2,deny"
```

#### 3. Use Specific Variables

**Slow** (inspects everything):
```apache
SecRule ARGS "@rx admin" "id:5010,phase:2,deny"
```

**Fast** (inspects only username):
```apache
SecRule ARGS:username "@rx admin" "id:5010,phase:2,deny"
```

#### 4. Skip Rules When Possible

```apache
# If safe mode enabled, skip expensive checks
SecRule REQUEST_HEADERS:X-Safe-Mode "@streq 1" "id:5020,phase:1,skipAfter:END_EXPENSIVE_CHECKS"

# Expensive regex checks
SecRule ARGS "@rx (very|complex|regex)" "id:5021,phase:2,deny"
SecRule ARGS "@rx (another|complex|regex)" "id:5022,phase:2,deny"

SecMarker END_EXPENSIVE_CHECKS
```

#### 5. Use @pm Instead of @rx for Multiple Strings

**Slow** (complex regex):
```apache
SecRule ARGS "@rx (union|select|insert|delete|drop)" "id:5030,phase:2,deny"
```

**Fast** (optimized phrase match):
```apache
SecRule ARGS "@pm union select insert delete drop" "id:5030,phase:2,deny"
```

### Regex Optimization

#### Anchor Patterns

**Slow** (scans entire string):
```apache
SecRule ARGS "@rx admin" "id:5040,phase:2,deny"
```

**Fast** (fails early if doesn't start with 'admin'):
```apache
SecRule ARGS "@rx ^admin" "id:5040,phase:2,deny"
```

#### Avoid Backtracking

**Dangerous** (catastrophic backtracking):
```apache
# DON'T USE: (a+)+ causes exponential time complexity
SecRule ARGS "@rx (a+)+(b+)+" "id:5050,phase:2,deny"
```

**Safe** (bounded, no backtracking):
```apache
SecRule ARGS "@rx ^[ab]{1,100}$" "id:5050,phase:2,deny"
```

#### Use Non-Capturing Groups

**Slower** (captures groups):
```apache
SecRule ARGS "@rx (union).*(select)" "id:5060,phase:2,deny"
```

**Faster** (no capturing overhead):
```apache
SecRule ARGS "@rx (?:union).*(?:select)" "id:5060,phase:2,deny"
```

### Profiling Rules

**Add timing middleware**:

```python
import time
from starlette.middleware.base import BaseHTTPMiddleware

class WAFProfiler(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start = time.time()
        response = await call_next(request)
        duration = time.time() - start

        if duration > 0.1:  # Log slow requests
            print(f"SLOW: {request.method} {request.url.path} - {duration:.3f}s")

        return response
```

---

## Debugging Rules

### Enable Debug Logging

```python
import logging

# Enable LeWAF debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("lewaf")
logger.setLevel(logging.DEBUG)
```

### Test Individual Rules

```python
from lewaf.integration import WAF

# Test single rule
config = {
    "rules": [
        'SecRule ARGS "@rx <script" "id:1,phase:2,deny,log,msg:\'XSS Test\'"'
    ],
    "rule_files": []
}

waf = WAF(config=config)
tx = waf.new_transaction()

# Simulate request
tx.process_uri("/?q=<script>alert(1)</script>", "GET")
result = tx.process_request_headers()

# Check if blocked
print(f"Blocked: {result is not None}")
print(f"Message: {result.get('message') if result else 'None'}")
```

### Debug Transformations

```python
# Test transformations manually
import urllib.parse

test_input = "%3Cscript%3E"

# URL decode
decoded = urllib.parse.unquote(test_input)
print(f"Decoded: {decoded}")  # <script>

# Lowercase
lowered = decoded.lower()
print(f"Lowered: {lowered}")  # <script>
```

### Common Debugging Questions

**Q: Why isn't my rule matching?**

1. Check phase - is variable available in that phase?
2. Check transformations - did you decode input?
3. Check regex - test pattern in regex tester
4. Check variable name - is it `ARGS` vs `ARGS:param`?

**Q: Why is my rule blocking legitimate requests?**

1. Pattern too broad - be more specific
2. Missing exceptions - add whitelisting rules
3. Wrong variable - inspecting too much

**Q: Why is my rule slow?**

1. Wrong phase - move to earlier phase if possible
2. Regex backtracking - simplify pattern
3. Too many transformations - remove unnecessary ones
4. Wrong operator - use `@pm` instead of `@rx` for multiple strings

---

## Best Practices Summary

### Do's ✅

- ✅ Test rules thoroughly before production
- ✅ Document why each rule exists
- ✅ Use specific patterns, not broad ones
- ✅ Apply appropriate transformations
- ✅ Choose the right phase for each check
- ✅ Use fast operators (`@pm`, `@streq`) when possible
- ✅ Monitor false positives in production
- ✅ Version control your rules

### Don'ts ❌

- ❌ Write rules for hypothetical threats
- ❌ Use complex regex without testing
- ❌ Inspect response bodies unless necessary
- ❌ Block without logging
- ❌ Forget to handle encoding
- ❌ Use capturing groups in regex
- ❌ Deploy untested rules to production
- ❌ Ignore false positives

---

## Next Steps

- **[API Reference](../api/reference.md)** - Complete LeWAF API documentation
- **[Django Integration](./integration-django.md)** - Integrate with Django
- **[FastAPI Integration](./integration-fastapi.md)** - Integrate with FastAPI
- **[Flask Integration](./integration-flask.md)** - Integrate with Flask
- **[Starlette Integration](./integration-starlette.md)** - Integrate with Starlette
- **[Performance Tuning](../performance/tuning.md)** - Optimize WAF performance
- **[Troubleshooting](../troubleshooting/runbook.md)** - Common issues and solutions

---

**Questions?** File an issue on GitHub or consult the community forums.
