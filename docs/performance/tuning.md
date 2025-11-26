# Performance Tuning Guide

**LeWAF Production Performance Optimization**

This guide provides strategies and best practices for optimizing LeWAF performance in production environments.

---

## Table of Contents

- [Overview](#overview)
- [Performance Metrics](#performance-metrics)
- [Configuration Optimization](#configuration-optimization)
- [Resource Allocation](#resource-allocation)
- [Caching Strategies](#caching-strategies)
- [Rule Optimization](#rule-optimization)
- [Load Balancer Integration](#load-balancer-integration)
- [CDN Integration](#cdn-integration)
- [Benchmarking](#benchmarking)
- [Monitoring Performance](#monitoring-performance)
- [Troubleshooting Performance Issues](#troubleshooting-performance-issues)

---

## Overview

LeWAF performance is influenced by several factors:

- **Rule complexity** - Number and complexity of security rules
- **Request characteristics** - Body size, headers, payload type
- **Resource allocation** - CPU, memory, I/O
- **Storage backend** - Memory vs. Redis performance
- **Network** - Latency, bandwidth, load balancing

### Performance Targets

| Metric | Target | Excellent |
|--------|--------|-----------|
| **Latency (p50)** | < 10ms | < 5ms |
| **Latency (p95)** | < 50ms | < 20ms |
| **Latency (p99)** | < 100ms | < 50ms |
| **Throughput** | > 1000 RPS | > 5000 RPS |
| **CPU Usage** | < 70% | < 50% |
| **Memory Usage** | < 80% | < 60% |
| **Error Rate** | < 0.1% | < 0.01% |

---

## Performance Metrics

### Key Metrics to Track

**1. Request Latency**
```bash
# Measure with curl
curl -w "Time: %{time_total}s\n" -o /dev/null -s http://localhost:8000/test

# View latency distribution
grep "request_duration" /app/logs/audit.log | \
  jq -r .request_duration | \
  sort -n | \
  awk '{sum+=$1; arr[NR]=$1} END {
    print "p50:", arr[int(NR*0.5)];
    print "p95:", arr[int(NR*0.95)];
    print "p99:", arr[int(NR*0.99)];
  }'
```

**2. Throughput (Requests Per Second)**
```bash
# Using Apache Bench
ab -n 10000 -c 100 http://localhost:8000/test

# Using wrk
wrk -t4 -c100 -d30s http://localhost:8000/test
```

**3. Rule Evaluation Time**
```bash
# Enable detailed logging
SecDebugLogLevel 9

# Analyze rule performance
grep "Rule.*took" /app/logs/debug.log | \
  awk '{print $3, $5}' | \
  sort -k2 -rn | \
  head -20
```

**4. Resource Usage**
```bash
# CPU and memory
top -p $(pgrep -f lewaf)

# Detailed Python profiling
python -m cProfile -o profile.stats lewaf_app.py
python -m pstats profile.stats
```

---

## Configuration Optimization

### 1. Rule Engine Mode

**Options**:

```apache
# Full protection (highest security, most overhead)
SecRuleEngine On

# Monitoring only (logging without blocking, minimal overhead)
SecRuleEngine DetectionOnly

# Disabled (no overhead)
SecRuleEngine Off
```

**Recommendation**: Use `DetectionOnly` during initial tuning to measure baseline performance.

### 2. Body Inspection

**Configuration**:

```apache
# Enable body inspection (required for POST/PUT)
SecRequestBodyAccess On
SecResponseBodyAccess Off  # Usually not needed, saves performance

# Set appropriate limits
SecRequestBodyLimit 13107200  # 12.5 MB
SecRequestBodyNoFilesLimit 131072  # 128 KB for non-file requests
SecRequestBodyLimitAction Reject
```

**Performance Impact**:
- Body inspection adds 2-10ms latency depending on size
- Disable response body inspection unless required
- Set lower limits for better performance

### 3. Audit Logging

**Configuration**:

```apache
# For production, log only blocked requests
SecAuditEngine RelevantOnly

# Use JSON format (easier to parse)
SecAuditLogFormat JSON

# Log to file or syslog
SecAuditLogType Serial
SecAuditLog /app/logs/audit.log

# Minimize logged parts
SecAuditLogParts ABCFHZ  # Exclude J (uploaded files)
```

**Performance Impact**:
- `RelevantOnly` reduces I/O by 90%+
- Excluding part J saves disk space
- Consider external logging (syslog, CloudWatch)

### 4. Debug Logging

```apache
# Production: disable debug logging
SecDebugLogLevel 0

# Development/troubleshooting only
# SecDebugLogLevel 3
# SecDebugLog /app/logs/debug.log
```

**Performance Impact**: Debug logging can reduce throughput by 30-50%.

---

## Resource Allocation

### CPU Allocation

**Guidelines**:

| Load | vCPUs | Description |
|------|-------|-------------|
| Light | 1-2 | < 100 RPS, simple rules |
| Medium | 2-4 | 100-1000 RPS, moderate rules |
| Heavy | 4-8+ | > 1000 RPS, complex rules |

**Configuration**:

```yaml
# Docker
deploy:
  resources:
    limits:
      cpus: '4'
    reservations:
      cpus: '2'

# Kubernetes
resources:
  requests:
    cpu: 2000m
  limits:
    cpu: 4000m
```

**Multi-Core Optimization**:

```python
# Set worker processes (1 per CPU core)
import multiprocessing
workers = multiprocessing.cpu_count()

# In Uvicorn
uvicorn.run(app, workers=workers)

# Environment variable
export LEWAF_WORKERS=4
```

### Memory Allocation

**Guidelines**:

| Load | Memory | Description |
|------|--------|-------------|
| Light | 512MB-1GB | Simple rules, no persistence |
| Medium | 1-2GB | Moderate rules, in-memory collections |
| Heavy | 2-4GB+ | Complex rules, large collections |

**Configuration**:

```yaml
# Docker
deploy:
  resources:
    limits:
      memory: 2G
    reservations:
      memory: 1G

# Kubernetes
resources:
  requests:
    memory: 1Gi
  limits:
    memory: 2Gi
```

**Memory Optimization**:

```apache
# Limit request body buffering
SecRequestBodyLimit 1048576  # 1 MB

# Use Redis for collections (offload memory)
export LEWAF_STORAGE_BACKEND=redis
export LEWAF_REDIS_URL=redis://localhost:6379/0
```

### I/O Optimization

**Strategies**:

1. **Use tmpfs for temporary files**:
   ```yaml
   # Docker Compose
   tmpfs:
     - /tmp:size=1G,mode=1777

   # Kubernetes
   volumes:
     - name: tmp
       emptyDir:
         medium: Memory
         sizeLimit: 1Gi
   ```

2. **External logging**:
   ```apache
   # Use syslog instead of file logging
   SecAuditLogType Syslog
   SecAuditLog /dev/log
   ```

3. **Disable file upload storage**:
   ```apache
   SecUploadKeepFiles Off
   ```

---

## Caching Strategies

### 1. Rule Compilation Caching

**Implementation**:

LeWAF automatically caches compiled regexes using `@lru_cache`:

```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def compile_regex(pattern):
    return re.compile(pattern)
```

**Performance Gain**: 50-70% improvement on repeated patterns.

### 2. IP List Caching

**Configuration**:

```python
from lewaf.storage import RedisBackend

# Use Redis for shared IP lists
storage = RedisBackend(
    url="redis://localhost:6379/0",
    ttl=3600  # 1 hour cache
)

# Collection configuration
SecAction "id:900000,phase:1,nolog,pass,\
  initcol:ip=%{REMOTE_ADDR}"
```

**Performance Gain**: 90% reduction in storage backend calls.

### 3. GeoIP Caching

**Configuration**:

```python
from functools import lru_cache
from geoip2 import database

reader = database.Reader('/path/to/GeoLite2-Country.mmdb')

@lru_cache(maxsize=10000)
def lookup_country(ip):
    return reader.country(ip).country.iso_code
```

**Performance Gain**: 80% reduction in GeoIP lookups.

### 4. Response Caching (CDN Integration)

**Configuration**:

```apache
# Set cache headers for static content
SecRule REQUEST_URI "@rx ^/static/" \
  "id:1001,phase:2,pass,\
   setenv:cache_control=public, max-age=86400"

# Vary by request characteristics
Header set Vary "Accept-Encoding, X-Forwarded-For"
```

---

## Rule Optimization

### 1. Paranoia Level Tuning

**Levels**:

| Level | Rules | False Positives | Performance |
|-------|-------|-----------------|-------------|
| 1 | ~90 | Low | Fast |
| 2 | ~150 | Medium | Moderate |
| 3 | ~200 | High | Slow |
| 4 | ~250 | Very High | Very Slow |

**Configuration**:

```apache
# Start with level 1
SecAction "id:900000,phase:1,nolog,pass,setvar:tx.paranoia_level=1"
```

**Performance Impact**: Level 1 vs. Level 4 can be 3-5x difference.

### 2. Disable Unused Rules

```apache
# Disable entire categories
SecRuleRemoveById 920000-920999  # Protocol enforcement

# Disable specific rules
SecRuleRemoveById 942100  # SQL injection

# Use ranges
SecRuleRemoveById 941000-941999  # XSS rules
```

**Performance Gain**: 10-30% per disabled category.

### 3. Optimize Regex Patterns

**Bad**:
```apache
# Slow - backtracking
SecRule ARGS "@rx .*attack.*" "id:1001,phase:2,deny"

# Slow - no anchors
SecRule ARGS "@rx (sql|union|select)" "id:1002,phase:2,deny"
```

**Good**:
```apache
# Fast - anchored
SecRule ARGS "@rx ^.*attack.*$" "id:1001,phase:2,deny"

# Fast - word boundaries
SecRule ARGS "@rx \b(sql|union|select)\b" "id:1002,phase:2,deny"

# Faster - use @contains for literal strings
SecRule ARGS "@contains attack" "id:1003,phase:2,deny"
```

### 4. Minimize Transformations

**Bad**:
```apache
# Too many transformations
SecRule ARGS "attack" \
  "id:1001,phase:2,deny,\
   t:lowercase,t:urlDecode,t:htmlEntityDecode,t:base64Decode,t:jsDecode"
```

**Good**:
```apache
# Only necessary transformations
SecRule ARGS "attack" \
  "id:1001,phase:2,deny,\
   t:lowercase,t:urlDecode"
```

**Performance Gain**: 20-40% per transformation removed.

### 5. Phase Optimization

**Guidelines**:

- **Phase 1**: Request headers only (fast)
- **Phase 2**: Request body (slower, but necessary)
- **Phase 3**: Response headers (usually not needed)
- **Phase 4**: Response body (expensive, avoid if possible)

```apache
# Check Content-Length in phase 1 (before body read)
SecRule REQUEST_HEADERS:Content-Length "@gt 10485760" \
  "id:1001,phase:1,deny,msg:'Request too large'"

# Body inspection in phase 2
SecRule ARGS "@rx attack" \
  "id:1002,phase:2,deny"

# Avoid phase 3/4 unless necessary
SecResponseBodyAccess Off
```

---

## Load Balancer Integration

### HAProxy Configuration

```haproxy
frontend lewaf_frontend
    bind *:80
    bind *:443 ssl crt /etc/haproxy/certs/

    # Health checks
    acl lewaf_healthy nbsrv(lewaf_backend) ge 1

    # Use least connections for balanced load
    default_backend lewaf_backend

backend lewaf_backend
    mode http
    balance leastconn

    # Health check
    option httpchk GET /health HTTP/1.1\r\nHost:\ localhost

    # Timeouts
    timeout connect 5s
    timeout server 30s

    # Servers
    server lewaf1 10.0.1.10:8000 check inter 5s fall 3 rise 2
    server lewaf2 10.0.1.11:8000 check inter 5s fall 3 rise 2
    server lewaf3 10.0.1.12:8000 check inter 5s fall 3 rise 2

    # Connection pooling
    http-reuse always
```

### Nginx Configuration

```nginx
upstream lewaf_backend {
    least_conn;

    # Servers
    server 10.0.1.10:8000 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8000 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:8000 max_fails=3 fail_timeout=30s;

    # Connection pooling
    keepalive 32;
}

server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://lewaf_backend;
        proxy_http_version 1.1;

        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;

        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;

        # Keep-alive
        proxy_set_header Connection "";
    }

    # Health check
    location /health {
        access_log off;
        proxy_pass http://lewaf_backend/health;
    }
}
```

### AWS ALB/NLB Configuration

```yaml
# Using Terraform
resource "aws_lb" "lewaf" {
  name               = "lewaf-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnets

  enable_http2 = true
  enable_deletion_protection = true
}

resource "aws_lb_target_group" "lewaf" {
  name     = "lewaf-tg"
  port     = 8000
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    enabled             = true
    path                = "/health"
    port                = "8000"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 3
    interval            = 30
    matcher             = "200"
  }

  deregistration_delay = 30

  stickiness {
    type            = "lb_cookie"
    cookie_duration = 3600
    enabled         = false
  }
}
```

### Session Affinity Considerations

**When to use**:
- Using memory-backed storage
- Stateful operations (sessions, rate limiting)

**When NOT to use**:
- Using Redis/database storage (shared state)
- Stateless operations

**Configuration**:
```haproxy
# HAProxy - IP hash
balance source

# Nginx - IP hash
ip_hash;

# AWS ALB - sticky sessions
stickiness enabled=true duration=3600
```

---

## CDN Integration

### CloudFlare Configuration

```javascript
// cloudflare-worker.js
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  // Pass through to LeWAF
  const response = await fetch(request)

  // Cache static content
  if (request.url.includes('/static/')) {
    const newResponse = new Response(response.body, response)
    newResponse.headers.set('Cache-Control', 'public, max-age=86400')
    return newResponse
  }

  return response
}
```

**Page Rules**:
```
*.example.com/static/*
  - Cache Level: Cache Everything
  - Edge Cache TTL: 1 month
  - Browser Cache TTL: 1 day

*.example.com/*
  - Cache Level: Bypass (dynamic content)
```

### Fastly Configuration

```vcl
sub vcl_recv {
  # Pass dynamic requests to LeWAF
  if (req.url !~ "^/static/") {
    return (pass);
  }

  # Cache static content
  return (hash);
}

sub vcl_backend_response {
  # Set cache headers for static content
  if (bereq.url ~ "^/static/") {
    set beresp.ttl = 1d;
    set beresp.grace = 1h;
  }
}
```

### Cache-Control Headers

```apache
# In LeWAF config
SecRule REQUEST_URI "@rx ^/static/" \
  "id:1001,phase:2,pass,\
   setenv:cache_control=public, max-age=86400"

# Dynamic content (no cache)
SecRule REQUEST_URI "@rx ^/api/" \
  "id:1002,phase:2,pass,\
   setenv:cache_control=no-cache, no-store, must-revalidate"
```

---

## Benchmarking

### Tools

**1. Apache Bench (ab)**:
```bash
# Simple benchmark
ab -n 10000 -c 100 http://localhost:8000/test

# With POST data
ab -n 1000 -c 50 -p post.txt -T application/json http://localhost:8000/api
```

**2. wrk (recommended)**:
```bash
# Basic test
wrk -t4 -c100 -d30s http://localhost:8000/test

# With custom script
wrk -t4 -c100 -d30s -s post.lua http://localhost:8000/api
```

**post.lua**:
```lua
wrk.method = "POST"
wrk.body   = '{"test":"data"}'
wrk.headers["Content-Type"] = "application/json"
```

**3. Locust (Python)**:
```python
from locust import HttpUser, task, between

class LeWAFUser(HttpUser):
    wait_time = between(1, 3)

    @task
    def test_endpoint(self):
        self.client.get("/test")

    @task(2)
    def test_api(self):
        self.client.post("/api", json={"test": "data"})
```

### Benchmark Scenarios

**Scenario 1: Baseline (No WAF)**:
```bash
# Measure without LeWAF
wrk -t4 -c100 -d30s http://backend:8080/test
```

**Scenario 2: WAF Detection Mode**:
```bash
# SecRuleEngine DetectionOnly
wrk -t4 -c100 -d30s http://localhost:8000/test
```

**Scenario 3: WAF Full Protection**:
```bash
# SecRuleEngine On
wrk -t4 -c100 -d30s http://localhost:8000/test
```

**Scenario 4: WAF with Attack Payloads**:
```bash
# Test with malicious payloads
wrk -t4 -c100 -d30s -s attack.lua http://localhost:8000/test
```

### Expected Results

| Scenario | Latency (p50) | Latency (p99) | Overhead |
|----------|---------------|---------------|----------|
| Baseline | 5ms | 15ms | - |
| Detection Only | 8ms | 25ms | +60% |
| Full Protection | 12ms | 40ms | +140% |
| With Attacks | 15ms | 50ms | +200% |

**Note**: Actual results depend on rule complexity and hardware.

---

## Monitoring Performance

### Prometheus Metrics

**Key metrics to monitor**:

```promql
# Request rate
rate(lewaf_requests_total[5m])

# Latency percentiles
histogram_quantile(0.50, lewaf_request_duration_seconds_bucket)
histogram_quantile(0.95, lewaf_request_duration_seconds_bucket)
histogram_quantile(0.99, lewaf_request_duration_seconds_bucket)

# Rule evaluation time
rate(lewaf_rule_evaluation_duration_seconds_sum[5m]) /
rate(lewaf_rule_evaluation_duration_seconds_count[5m])

# Resource usage
process_cpu_seconds_total
process_resident_memory_bytes
```

### Grafana Dashboard

**Panels**:

1. **Request Rate** (Graph)
   - Query: `rate(lewaf_requests_total[5m])`

2. **Latency Distribution** (Graph)
   - p50, p95, p99 lines

3. **Resource Usage** (Gauge)
   - CPU usage %
   - Memory usage %

4. **Error Rate** (Graph)
   - Query: `rate(lewaf_errors_total[5m])`

5. **Top Slow Rules** (Table)
   - Rule ID, Avg time, Call count

---

## Troubleshooting Performance Issues

### Issue: High Latency

**Diagnosis**:
```bash
# Profile rule execution
SecDebugLogLevel 9
grep "Rule.*took" /app/logs/debug.log | sort -k6 -rn | head -10

# Check for slow transformations
grep "Transformation" /app/logs/debug.log | grep "took"

# Monitor system resources
top -p $(pgrep -f lewaf)
```

**Solutions**:
1. Reduce paranoia level
2. Disable slow rules
3. Optimize regex patterns
4. Reduce transformations

### Issue: High CPU Usage

**Diagnosis**:
```bash
# CPU profiling
python -m cProfile -o profile.stats lewaf_app.py
python -m pstats profile.stats
> sort cumulative
> stats 20
```

**Solutions**:
1. Scale horizontally (add instances)
2. Optimize rules
3. Use rule caching
4. Reduce debug logging

### Issue: High Memory Usage

**Diagnosis**:
```bash
# Memory profiling
pip install memory_profiler
python -m memory_profiler lewaf_app.py
```

**Solutions**:
1. Use Redis for collections
2. Reduce body limits
3. Clear old collections
4. Increase memory allocation

---

## Best Practices Summary

1. **Start Simple**: Begin with paranoia level 1, increase gradually
2. **Measure Baseline**: Benchmark before and after changes
3. **Monitor Continuously**: Use Prometheus + Grafana
4. **Optimize Rules**: Disable unused, optimize regex
5. **Scale Horizontally**: Add instances before vertical scaling
6. **Use Caching**: Regex, IP lists, GeoIP
7. **External Storage**: Use Redis for shared state
8. **Minimize Logging**: RelevantOnly for audit logs
9. **Load Balance**: Use least connections
10. **Test Regularly**: Benchmark after configuration changes

---

## Next Steps

- **Security Hardening**: See [../security/hardening.md](../security/hardening.md)
- **Monitoring Setup**: See [../monitoring/prometheus.md](../monitoring/prometheus.md)
- **Troubleshooting**: See [../troubleshooting/runbook.md](../troubleshooting/runbook.md)

---

**Questions or Issues?**
- GitHub Issues: https://github.com/abilian/lewaf/issues
- Documentation: https://lewaf.readthedocs.io
