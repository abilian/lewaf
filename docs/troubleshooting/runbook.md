# Troubleshooting Runbook

**LeWAF Production Troubleshooting Guide**

This runbook provides step-by-step troubleshooting procedures for common issues, performance problems, and emergency situations.

---

## Table of Contents

- [Quick Reference](#quick-reference)
- [Common Issues](#common-issues)
- [Performance Issues](#performance-issues)
- [Configuration Issues](#configuration-issues)
- [Storage Issues](#storage-issues)
- [Rule Issues](#rule-issues)
- [Body Processing Issues](#body-processing-issues)
- [Integration Issues](#integration-issues)
- [Emergency Procedures](#emergency-procedures)
- [Log Analysis](#log-analysis)
- [Diagnostic Commands](#diagnostic-commands)

---

## Quick Reference

### Severity Levels

| Level | Response Time | Description |
|-------|---------------|-------------|
| **P0 - Critical** | Immediate | Service down, data loss |
| **P1 - High** | < 1 hour | Major feature broken |
| **P2 - Medium** | < 4 hours | Minor feature broken |
| **P3 - Low** | < 24 hours | Enhancement or minor bug |

### Error Code Categories

See [error-codes.md](error-codes.md) for complete reference.

| Category | Code Range | Description |
|----------|------------|-------------|
| Configuration | WAF-0xxx | Configuration errors |
| Parsing | PARSE-1xxx | Rule parsing errors |
| Rule Evaluation | RULE-2xxx | Rule execution errors |
| Body Processing | BODY-3xxx | Request body errors |
| Operators | OP-4xxx | Operator errors |
| Integration | INT-5xxx | Framework integration errors |
| Storage | STORE-6xxx | Backend storage errors |
| Proxy | PROXY-7xxx | Upstream proxy errors |

---

## Common Issues

### Issue 1: High Latency (P1)

**Symptoms**:
- Requests taking > 500ms
- Timeout errors
- Increased response times

**Diagnosis**:

```bash
# Check current latency
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8000/health

# Monitor request times in logs
grep "request_duration" /app/logs/audit.log | tail -50

# Check resource usage
top -p $(pgrep -f lewaf)
```

**Common Causes**:

1. **Too many rules enabled**
   - **Solution**: Reduce paranoia level or disable unused rules
   ```apache
   # In crs-setup.conf
   SecAction "id:900000,phase:1,nolog,pass,setvar:tx.paranoia_level=1"
   ```

2. **Large request bodies**
   - **Solution**: Check body size limits
   ```apache
   SecRequestBodyLimit 13107200  # 12.5 MB
   ```

3. **Regex performance**
   - **Solution**: Profile rules to identify slow regexes
   ```bash
   # Enable performance logging
   SecDebugLogLevel 9
   grep "Rule execution time" /app/logs/debug.log | sort -k4 -n
   ```

4. **Storage backend slow**
   - **Solution**: Check Redis/database latency
   ```bash
   # Test Redis latency
   redis-cli --latency -h redis-host
   ```

**Resolution Steps**:

1. Identify bottleneck (rules vs. body processing vs. storage)
2. Apply appropriate optimization
3. Monitor latency improvement
4. Document changes

---

### Issue 2: High Memory Usage (P1)

**Symptoms**:
- Memory usage > 80%
- OOM kills
- Swap usage increasing

**Diagnosis**:

```bash
# Check memory usage
ps aux | grep lewaf
free -h

# Python memory profiling
pip install memory_profiler
python -m memory_profiler lewaf_app.py
```

**Common Causes**:

1. **Large collections in memory**
   - **Error Code**: STORE-6001
   - **Solution**: Use Redis for persistent collections
   ```python
   from lewaf.storage import RedisBackend
   storage = RedisBackend(url="redis://localhost:6379/0")
   ```

2. **Request body buffering**
   - **Solution**: Reduce body limit
   ```apache
   SecRequestBodyLimit 1048576  # 1 MB
   ```

3. **Memory leak**
   - **Solution**: Restart service, collect heap dump
   ```bash
   # Restart service
   systemctl restart lewaf

   # Collect heap dump (Python)
   pip install pympler
   python -c "from pympler import tracker; tr = tracker.SummaryTracker(); tr.print_diff()"
   ```

**Resolution Steps**:

1. Check if memory leak or legitimate growth
2. If leak: restart service, schedule investigation
3. If growth: tune body limits and collection size
4. Monitor memory after changes

---

### Issue 3: Service Won't Start (P0)

**Symptoms**:
- Service fails to start
- Immediate crash
- Exit code != 0

**Diagnosis**:

```bash
# Check service status
systemctl status lewaf

# Check logs
journalctl -u lewaf -n 50 --no-pager

# Manual start for debugging
/usr/bin/lewaf --config /etc/lewaf/lewaf.conf --debug
```

**Common Causes**:

1. **Configuration file not found**
   - **Error Code**: WAF-0002
   ```
   [WAF-0002] Configuration file not found: /etc/lewaf/lewaf.conf
   ```
   - **Solution**: Verify file path and permissions
   ```bash
   ls -la /etc/lewaf/lewaf.conf
   chmod 644 /etc/lewaf/lewaf.conf
   ```

2. **Invalid configuration syntax**
   - **Error Code**: WAF-0003
   ```
   [WAF-0003] Configuration validation failed: Invalid directive 'SecRulEngien'
   ```
   - **Solution**: Fix syntax error
   ```bash
   # Validate configuration
   lewaf --config /etc/lewaf/lewaf.conf --test
   ```

3. **Port already in use**
   - **Error Code**: INT-5001
   ```
   [INT-5001] Failed to bind to port 8000: Address already in use
   ```
   - **Solution**: Change port or kill existing process
   ```bash
   # Find process using port
   lsof -i :8000
   kill <pid>

   # Or change port in config
   # In lewaf startup: --port 8001
   ```

4. **Missing dependencies**
   ```
   ModuleNotFoundError: No module named 'redis'
   ```
   - **Solution**: Install dependencies
   ```bash
   pip install lewaf[redis]
   ```

**Resolution Steps**:

1. Check error message for error code
2. Refer to error code documentation
3. Fix underlying issue
4. Verify service starts successfully
5. Check logs for warnings

---

### Issue 4: Requests Being Blocked Incorrectly (P2)

**Symptoms**:
- Legitimate requests blocked
- False positives
- Error Code: RULE-2xxx

**Diagnosis**:

```bash
# Check audit logs for blocked requests
grep '"action":"block"' /app/logs/audit.log | tail -20

# Find which rule triggered
grep 'rule_id' /app/logs/audit.log | grep <transaction_id>

# Check anomaly score
grep 'anomaly_score' /app/logs/audit.log | grep <transaction_id>
```

**Common Causes**:

1. **Paranoia level too high**
   - **Solution**: Reduce paranoia level
   ```apache
   # In crs-setup.conf
   SecAction "id:900000,phase:1,nolog,pass,setvar:tx.paranoia_level=1"
   ```

2. **Specific rule too strict**
   - **Solution**: Disable or tune rule
   ```apache
   # Disable specific rule
   SecRuleRemoveById 942100

   # Or add exception
   SecRule REQUEST_URI "@contains /api/upload" \
     "id:1000,phase:1,pass,ctl:ruleRemoveById=942100"
   ```

3. **Anomaly threshold too low**
   - **Solution**: Increase threshold
   ```apache
   SecAction "id:900110,phase:1,nolog,pass,\
     setvar:tx.inbound_anomaly_score_threshold=10"
   ```

**Resolution Steps**:

1. Identify transaction ID from application logs
2. Search audit logs for transaction details
3. Identify triggering rule(s)
4. Evaluate if true or false positive
5. If false positive: create rule exception
6. Test with original request
7. Document exception in runbook

---

### Issue 5: Request Bodies Not Being Inspected (P2)

**Symptoms**:
- POST requests not checked
- File uploads not scanned
- ARGS_POST variables empty

**Diagnosis**:

```bash
# Check if body inspection is enabled
grep "SecRequestBodyAccess" /etc/lewaf/lewaf.conf

# Check body processor logs
grep "BODY-" /app/logs/audit.log | tail -20

# Test body inspection
curl -X POST -d "test=value" http://localhost:8000/test -v
```

**Common Causes**:

1. **Body access disabled**
   - **Solution**: Enable in configuration
   ```apache
   SecRequestBodyAccess On
   ```

2. **Body size exceeds limit**
   - **Error Code**: BODY-3003
   ```
   [BODY-3003] Body size 15000000 exceeds limit 13107200
   ```
   - **Solution**: Increase limit or reject large bodies
   ```apache
   SecRequestBodyLimit 20971520  # 20 MB
   SecRequestBodyLimitAction Reject
   ```

3. **Content-Type not recognized**
   - **Error Code**: BODY-3001 (JSON), BODY-3002 (XML)
   - **Solution**: Add content type to allowed list
   ```apache
   SecAction "id:900200,phase:1,nolog,pass,\
     setvar:tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |application/json| |application/xml|"
   ```

4. **Body processor failed**
   - **Error Code**: BODY-3001, BODY-3002, BODY-3004
   - **Solution**: Check REQBODY_ERROR variable
   ```bash
   grep "REQBODY_ERROR" /app/logs/audit.log
   ```

**Resolution Steps**:

1. Verify SecRequestBodyAccess On
2. Check body size limits
3. Verify Content-Type header
4. Check for body processor errors
5. Test with sample request

---

### Issue 6: Storage Backend Connection Failed (P1)

**Symptoms**:
- Collections not persisting
- Connection errors in logs
- Error Code: STORE-6001

**Diagnosis**:

```bash
# Test Redis connection
redis-cli -h <redis-host> -p 6379 ping

# Check connection in logs
grep "STORE-6001" /app/logs/audit.log

# Verify environment variable
echo $LEWAF_REDIS_URL
```

**Common Causes**:

1. **Redis not running**
   ```bash
   # Check Redis status
   systemctl status redis

   # Start Redis
   systemctl start redis
   ```

2. **Wrong connection URL**
   - **Solution**: Fix environment variable
   ```bash
   export LEWAF_REDIS_URL="redis://localhost:6379/0"
   ```

3. **Network connectivity**
   ```bash
   # Test connectivity
   telnet redis-host 6379
   nc -zv redis-host 6379
   ```

4. **Authentication required**
   ```bash
   # Add password to URL
   export LEWAF_REDIS_URL="redis://:password@localhost:6379/0"
   ```

**Resolution Steps**:

1. Verify Redis is running
2. Test network connectivity
3. Verify connection string
4. Check authentication
5. Restart LeWAF service

---

## Performance Issues

### High CPU Usage

**Diagnosis**:

```bash
# Check CPU usage
top -p $(pgrep -f lewaf)

# Python profiling
python -m cProfile -o profile.stats lewaf_app.py
python -m pstats profile.stats
```

**Common Causes**:

1. **Too many regex evaluations**
   - **Solution**: Optimize rules, reduce paranoia level

2. **Transformation overhead**
   - **Solution**: Minimize transformations
   ```apache
   # Bad - multiple transformations
   SecRule ARGS "attack" "t:lowercase,t:urlDecode,t:htmlEntityDecode,t:base64Decode"

   # Good - only necessary transformations
   SecRule ARGS "attack" "t:lowercase,t:urlDecode"
   ```

3. **Large request rate**
   - **Solution**: Scale horizontally, add instances

---

### Slow Rule Evaluation

**Diagnosis**:

```bash
# Enable rule performance logging
SecDebugLogLevel 9

# Find slow rules
grep "Rule.*took" /app/logs/debug.log | sort -k6 -n | tail -20
```

**Solutions**:

1. **Optimize regex patterns**
   - Use anchors (^, $)
   - Avoid greedy quantifiers (.*)
   - Use possessive quantifiers where possible

2. **Disable unused rules**
   ```apache
   SecRuleRemoveById 920000-920999
   ```

3. **Use rule caching**
   ```python
   from lewaf.cache import RuleCache
   cache = RuleCache(max_size=1000)
   ```

---

## Configuration Issues

### Include File Not Found

**Error Code**: PARSE-1002

```
[PARSE-1002] Include recursion detected or file not found: /app/rules/crs-setup.conf
```

**Solutions**:

1. **Check file path**
   ```bash
   ls -la /app/rules/crs-setup.conf
   ```

2. **Use absolute paths**
   ```apache
   Include /app/rules/crs-setup.conf
   ```

3. **Check permissions**
   ```bash
   chmod 644 /app/rules/*.conf
   ```

---

### Unknown Operator

**Error Code**: PARSE-1003

```
[PARSE-1003] Unknown operator: @rxxx
```

**Solutions**:

1. **Fix typo**
   ```apache
   # Wrong
   SecRule ARGS "@rxxx ^attack$"

   # Correct
   SecRule ARGS "@rx ^attack$"
   ```

2. **Check operator is registered**
   ```python
   from lewaf.primitives.operators import get_operator
   print(get_operator("rx"))
   ```

---

## Storage Issues

### Collection Data Lost

**Error Code**: STORE-6002

**Diagnosis**:

```bash
# Check if using memory storage (non-persistent)
grep "storage_backend" /etc/lewaf/lewaf.conf

# Check Redis data
redis-cli
> KEYS lewaf:*
```

**Solutions**:

1. **Use persistent backend**
   ```python
   from lewaf.storage import RedisBackend
   storage = RedisBackend(url="redis://localhost:6379/0")
   ```

2. **Enable Redis persistence**
   ```bash
   # In redis.conf
   save 900 1
   save 300 10
   save 60 10000
   appendonly yes
   ```

---

## Rule Issues

### Rule Parsing Failed

**Error Code**: PARSE-1001

```
[PARSE-1001] Failed to parse SecRule: Invalid operator syntax
```

**Diagnosis**:

```bash
# Test rule syntax
lewaf-tool validate-rule "SecRule ARGS \"@rx ^attack$\" \"id:1000,phase:2,deny\""
```

**Common Syntax Errors**:

1. **Missing quotes**
   ```apache
   # Wrong
   SecRule ARGS @rx ^attack$

   # Correct
   SecRule ARGS "@rx ^attack$"
   ```

2. **Invalid action syntax**
   ```apache
   # Wrong
   SecRule ARGS "@rx ^attack$" "id:1000,deny,phase:2"

   # Correct (phase before actions)
   SecRule ARGS "@rx ^attack$" "id:1000,phase:2,deny"
   ```

---

### Rule Not Triggering

**Diagnosis**:

```bash
# Enable debug logging
SecDebugLogLevel 9

# Check rule execution
grep "Rule 1000" /app/logs/debug.log
```

**Common Causes**:

1. **Wrong phase**
   ```apache
   # POST body checked in phase 2
   SecRule ARGS_POST "@rx attack" "id:1000,phase:2,deny"
   ```

2. **Variable not populated**
   ```bash
   # Check variable in debug log
   grep "ARGS_POST" /app/logs/debug.log
   ```

3. **Transformation changes value**
   ```apache
   # Without transformation
   SecRule ARGS "@rx Attack" "id:1000,phase:2,deny"

   # With lowercase transformation
   SecRule ARGS "@rx attack" "id:1000,phase:2,deny,t:lowercase"
   ```

---

## Body Processing Issues

### JSON Parsing Failed

**Error Code**: BODY-3001

```
[BODY-3001] Invalid JSON syntax: Expecting ',' delimiter
```

**Diagnosis**:

```bash
# Check request body
grep "BODY-3001" /app/logs/audit.log

# Get body snippet from error
grep "body_snippet" /app/logs/audit.log | grep <transaction_id>
```

**Solutions**:

1. **Validate JSON before sending**
   ```python
   import json
   try:
       json.loads(body)
   except json.JSONDecodeError as e:
       print(f"Invalid JSON: {e}")
   ```

2. **Set error variables for inspection**
   ```apache
   # Check REQBODY_ERROR
   SecRule REQBODY_ERROR "@eq 1" "id:1001,phase:2,log,deny"
   ```

---

### XML Parsing Failed

**Error Code**: BODY-3002

```
[BODY-3002] Invalid XML: mismatched tag
```

**Solutions**:

1. **Validate XML**
   ```python
   import xml.etree.ElementTree as ET
   try:
       ET.fromstring(body)
   except ET.ParseError as e:
       print(f"Invalid XML: {e}")
   ```

2. **Check encoding**
   ```bash
   file -i request.xml
   # Ensure UTF-8 encoding
   iconv -f ISO-8859-1 -t UTF-8 request.xml > request_utf8.xml
   ```

---

### Multipart Parsing Failed

**Error Code**: BODY-3004

```
[BODY-3004] Invalid multipart format: Missing boundary
```

**Solutions**:

1. **Verify Content-Type header**
   ```bash
   curl -X POST -H "Content-Type: multipart/form-data; boundary=----Boundary" ...
   ```

2. **Check boundary in body**
   ```bash
   # Body should start with: ------Boundary
   ```

---

## Integration Issues

### ASGI Middleware Error

**Error Code**: INT-5001

```
[INT-5001] ASGI middleware error: Failed to process request
```

**Diagnosis**:

```bash
# Check middleware initialization
grep "INT-5001" /app/logs/audit.log

# Verify middleware is registered
# In FastAPI
app.add_middleware(LeWAFMiddleware)
```

**Solutions**:

1. **Check middleware order**
   ```python
   # LeWAF should be early in middleware stack
   app.add_middleware(LeWAFMiddleware)
   app.add_middleware(CORSMiddleware)
   ```

2. **Verify configuration path**
   ```python
   middleware = LeWAFMiddleware(
       app,
       config_path="/etc/lewaf/lewaf.conf"
   )
   ```

---

## Emergency Procedures

### Procedure 1: Immediate Service Disable

**When**: Service causing widespread issues (P0)

**Steps**:

```bash
# 1. Disable WAF (bypass mode)
echo "SecRuleEngine DetectionOnly" > /etc/lewaf/bypass.conf
systemctl restart lewaf

# 2. Or remove from request path
# In nginx:
proxy_pass http://backend;  # Skip WAF

# 3. Monitor for issue resolution
tail -f /var/log/nginx/access.log
```

---

### Procedure 2: Emergency Restart

**When**: Service unresponsive, high resource usage

**Steps**:

```bash
# 1. Graceful restart
systemctl restart lewaf

# 2. If hung, force kill
pkill -9 -f lewaf
systemctl start lewaf

# 3. Verify service is running
systemctl status lewaf
curl http://localhost:8000/health
```

---

### Procedure 3: Rollback Configuration

**When**: Recent config change caused issues

**Steps**:

```bash
# 1. Restore previous config
cp /etc/lewaf/lewaf.conf.backup /etc/lewaf/lewaf.conf

# 2. Validate config
lewaf --config /etc/lewaf/lewaf.conf --test

# 3. Restart service
systemctl restart lewaf

# 4. Verify
curl http://localhost:8000/health
```

---

### Procedure 4: Enable Debug Logging

**When**: Need detailed diagnostics

**Steps**:

```bash
# 1. Edit config
SecDebugLogLevel 9
SecDebugLog /app/logs/debug.log

# 2. Restart service
systemctl restart lewaf

# 3. Monitor debug log
tail -f /app/logs/debug.log

# 4. Disable after debugging (performance impact)
SecDebugLogLevel 0
systemctl restart lewaf
```

---

## Log Analysis

### Structured Log Format

All errors follow this format:

```json
{
  "timestamp": "2025-11-13T10:30:45.123Z",
  "error_code": "BODY-3001",
  "error_category": "body_processing",
  "message": "Invalid JSON syntax",
  "context": {
    "transaction_id": "tx-123",
    "rule_id": 1000,
    "phase": 2,
    "variable": "ARGS:id"
  }
}
```

### Common Log Patterns

**1. Find all errors for a transaction**:

```bash
grep "tx-123" /app/logs/audit.log | jq .
```

**2. Count errors by type**:

```bash
grep "error_code" /app/logs/audit.log | \
  jq -r .error_code | \
  sort | uniq -c | sort -rn
```

**3. Find slow requests**:

```bash
grep "request_duration" /app/logs/audit.log | \
  jq 'select(.request_duration > 1.0)' | \
  jq -r '[.timestamp, .request_duration, .transaction_id] | @tsv'
```

**4. Analyze blocked requests**:

```bash
grep '"action":"block"' /app/logs/audit.log | \
  jq -r '[.timestamp, .transaction_id, .rule_id, .message] | @tsv'
```

---

## Diagnostic Commands

### System Health

```bash
# Service status
systemctl status lewaf

# Resource usage
top -p $(pgrep -f lewaf)
ps aux | grep lewaf

# Network connections
netstat -tulpn | grep 8000
ss -tulpn | grep 8000
```

### Log Analysis

```bash
# Recent errors
tail -100 /app/logs/audit.log | grep "error_code"

# Error counts
grep "error_code" /app/logs/audit.log | \
  jq -r .error_code | sort | uniq -c

# Transaction search
grep "tx-123" /app/logs/audit.log | jq .
```

### Configuration Validation

```bash
# Test configuration
lewaf --config /etc/lewaf/lewaf.conf --test

# Validate rules
lewaf-tool validate-rules /app/rules/*.conf

# Check syntax
grep -n "SecRule" /etc/lewaf/lewaf.conf | head -20
```

### Performance Analysis

```bash
# Request latency
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8000/test

# Where curl-format.txt contains:
# time_total: %{time_total}\n

# Rule performance
grep "Rule.*took" /app/logs/debug.log | sort -k6 -n | tail -20
```

---

## Next Steps

- **Error Codes Reference**: See [error-codes.md](error-codes.md)
- **Performance Tuning**: See [../performance/tuning.md](../performance/tuning.md)
- **Security Hardening**: See [../security/hardening.md](../security/hardening.md)
- **Monitoring**: See [../monitoring/prometheus.md](../monitoring/prometheus.md)

---

**Questions or Issues?**
- GitHub Issues: https://github.com/yourorg/lewaf/issues
- Documentation: https://lewaf.readthedocs.io
