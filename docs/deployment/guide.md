# LeWAF Production Deployment Guide

**Version**: 0.7.0
**Last Updated**: 2025-11-26
**Status**: Bêta

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [CRS Rule Loading](#crs-rule-loading)
6. [Framework Integration](#framework-integration)
7. [Monitoring & Logging](#monitoring--logging)
8. [Performance Tuning](#performance-tuning)
9. [Security Hardening](#security-hardening)
10. [Troubleshooting](#troubleshooting)

---

## Quick Start

### 5-Minute Setup

```bash
# 1. Install LeWAF
cd /path/to/lewaf
uv sync

# 2. Verify installation
uv run pytest -q  # Should show 393 passed

# 3. Create basic deployment
cat > app.py << 'EOF'
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from lewaf.integrations.starlette import WAFMiddleware

def homepage(request):
    return PlainTextResponse("Hello, WAF-protected World!")

app = Starlette(routes=[Route("/", homepage)])

# Add WAF with CRS rules
app.add_middleware(
    WAFMiddleware,
    config={
        "rule_files": ["coraza.conf"],  # Loads 594 CRS rules
        "engine": "DetectionOnly",      # Start in detection mode
    }
)
EOF

# 4. Run application
uv run uvicorn app:app --host 0.0.0.0 --port 8000

# 5. Test protection
curl "http://localhost:8000/?test=<script>alert('xss')</script>"
# Check logs for detection
```

---

## System Requirements

### Minimum Requirements

- **Python**: 3.9 or higher (3.12 recommended)
- **Memory**: 512 MB RAM (1 GB recommended)
- **CPU**: 1 core (2+ cores recommended)
- **Disk**: 100 MB for LeWAF + rules

### Recommended for Production

- **Python**: 3.12+
- **Memory**: 2 GB+ RAM
- **CPU**: 4+ cores for high traffic
- **Disk**: 1 GB+ for logs
- **OS**: Linux (Ubuntu 22.04, RHEL 8+, Debian 11+)

### Dependencies

```toml
# All dependencies managed by uv
python = "^3.9"
starlette = "^0.37.0"  # For ASGI/web integration
uvicorn = "^0.30.0"    # ASGI server
```

---

## Installation

### Production Installation

```bash
# 1. Clone repository
git clone https://github.com/yourorg/lewaf.git
cd lewaf

# 2. Install with uv
uv sync --frozen

# 3. Verify installation
uv run pytest tests/ -q
# Should see: 393 passed in ~1s

# 4. Check rule files
ls -lh rules/
# Should see 25 CRS .conf files
```

### Docker Installation

```dockerfile
# Dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install uv
RUN pip install uv

# Copy application
COPY .. /app/

# Install dependencies
RUN uv sync --frozen

# Expose port
EXPOSE 8000

# Run application
CMD ["uv", "run", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
# Build and run
docker build -t lewaf-app .
docker run -p 8000:8000 lewaf-app
```

---

## Configuration

### Basic Configuration

Create `waf_config.py`:

```python
"""WAF configuration for production."""

WAF_CONFIG = {
    # Rule engine mode
    "engine": "On",  # "On", "DetectionOnly", or "Off"

    # Rule files to load
    "rule_files": [
        "coraza.conf",  # Main CRS configuration (loads 594 rules)
    ],

    # Custom rules (optional)
    "custom_rules": [
        'SecRule ARGS:admin "@rx ^true$" "id:9001,phase:1,deny,msg:\'Admin parameter blocked\'"',
    ],

    # Request body limits
    "request_body_limit": 13107200,  # 12.5 MB
    "request_body_in_memory_limit": 131072,  # 128 KB

    # Response body limits
    "response_body_limit": 524288,  # 512 KB

    # Audit logging
    "audit_log": "/var/log/lewaf/audit.log",
    "audit_log_parts": "ABIJDEFHZ",

    # Performance
    "regex_cache_size": 128,  # LRU cache size
}
```

### Environment-Specific Configuration

```python
"""Environment-specific configurations."""
import os

# Determine environment
ENV = os.getenv("ENV", "production")

# Base configuration
BASE_CONFIG = {
    "rule_files": ["coraza.conf"],
    "request_body_limit": 13107200,
}

# Environment overrides
CONFIGS = {
    "development": {
        **BASE_CONFIG,
        "engine": "DetectionOnly",
        "audit_log": "./logs/audit-dev.log",
    },

    "staging": {
        **BASE_CONFIG,
        "engine": "DetectionOnly",
        "audit_log": "/var/log/lewaf/audit-staging.log",
    },

    "production": {
        **BASE_CONFIG,
        "engine": "On",  # Blocking mode
        "audit_log": "/var/log/lewaf/audit-prod.log",
        "audit_log_parts": "ABIJDEFHZ",
    },
}

# Get current config
WAF_CONFIG = CONFIGS[ENV]
```

---

## CRS Rule Loading

### Loading CRS Rules

The `coraza.conf` file automatically loads all 594 CRS rules:

```python
from lewaf.integration import WAF
from lewaf.seclang import SecLangParser

# Create WAF
waf = WAF({})

# Load CRS rules
parser = SecLangParser(waf)
parser.from_file("coraza.conf")

# Verify rules loaded
total_rules = sum(len(rules) for rules in waf.rule_group.rules_by_phase.values())
print(f"Loaded {total_rules} rules")  # Should print: Loaded 594 rules
```

### Custom Rule Files

```python
# Load custom rules in addition to CRS
parser.from_file("coraza.conf")  # Load CRS
parser.from_file("custom/my-rules.conf")  # Load custom rules
```

### Inline Rules

```python
# Add rules programmatically
parser.from_string('''
# Custom application rules
SecRule ARGS:action "@streq delete" "id:10001,phase:2,deny,msg:'Delete action blocked'"
SecRule REQUEST_HEADERS:X-Admin "@rx ^true$" "id:10002,phase:1,deny,msg:'Admin header forbidden'"
''')
```

### Rule Categories Loaded

When loading `coraza.conf`, you get:

| Category | File | Rules | Purpose |
|----------|------|-------|---------|
| Protocol Enforcement | REQUEST-920 | 103 | HTTP protocol validation |
| SQL Injection | REQUEST-942 | 73 | SQLi prevention |
| XSS | REQUEST-941 | 43 | Cross-site scripting |
| RCE | REQUEST-932 | 54 | Remote code execution |
| PHP Injection | REQUEST-933 | 27 | PHP attack prevention |
| Java Attacks | REQUEST-944 | 24 | Java-specific attacks |
| **Total** | **23 files** | **594** | **Complete protection** |

---

## Framework Integration

### Starlette / FastAPI

```python
"""Production Starlette/FastAPI integration."""
from starlette.applications import Starlette
from starlette.middleware import Middleware
from lewaf.integrations.starlette import WAFMiddleware
from waf_config import WAF_CONFIG

# Create middleware
middleware = [
    Middleware(
        WAFMiddleware,
        config=WAF_CONFIG
    )
]

# Create application
app = Starlette(
    routes=[...],
    middleware=middleware
)

# Or for FastAPI
from fastapi import FastAPI

app = FastAPI()
app.add_middleware(WAFMiddleware, config=WAF_CONFIG)
```

### ASGI Direct Integration

```python
"""Direct ASGI integration."""
from lewaf.integration import WAF
from lewaf.seclang import SecLangParser

class WAFMiddleware:
    def __init__(self, app, waf_config):
        self.app = app
        self.waf = WAF(waf_config)

        # Load rules
        parser = SecLangParser(self.waf)
        for rule_file in waf_config.get("rule_files", []):
            parser.from_file(rule_file)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Create transaction
        tx = self.waf.new_transaction(
            transaction_id=scope.get("request_id", "unknown")
        )

        # Process request
        client = scope.get("client", ("0.0.0.0", 0))
        server = scope.get("server", ("0.0.0.0", 8000))

        tx.process_connection(
            client_addr=client[0],
            client_port=client[1],
            server_addr=server[0],
            server_port=server[1]
        )

        # Process URI
        path = scope.get("path", "/")
        method = scope.get("method", "GET")
        tx.process_uri(path, method)

        # Process headers
        for name, value in scope.get("headers", []):
            tx.add_request_header(name.decode(), value.decode())

        # Evaluate phase 1 rules
        self.waf.evaluate_rules(tx, phase=1)

        # Check for blocking
        if tx.interruption:
            # Return blocked response
            await send({
                "type": "http.response.start",
                "status": tx.interruption.get("status", 403),
                "headers": [[b"content-type", b"text/plain"]],
            })
            await send({
                "type": "http.response.body",
                "body": b"Request blocked by WAF",
            })
            return

        # Continue to application
        await self.app(scope, receive, send)

# Use middleware
app = WAFMiddleware(app, WAF_CONFIG)
```

### Nginx Integration (Proxy Mode)

```nginx
# /etc/nginx/sites-available/app.conf

upstream lewaf_backend {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name example.com;

    # Pass to LeWAF-protected application
    location / {
        proxy_pass http://lewaf_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://lewaf_backend/health;
    }
}
```

---

## Monitoring & Logging

### Application Logging

```python
"""Production logging configuration."""
import logging
import logging.handlers

def setup_logging():
    """Configure production logging."""

    # Create logger
    logger = logging.getLogger("lewaf")
    logger.setLevel(logging.INFO)

    # Console handler (for Docker/systemd)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console.setFormatter(console_format)
    logger.addHandler(console)

    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        '/var/log/lewaf/app.log',
        maxBytes=10_000_000,  # 10 MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)

    return logger

# Initialize logging
logger = setup_logging()
```

### Metrics Collection

```python
"""WAF metrics for monitoring."""
from dataclasses import dataclass
from typing import Dict
import time

@dataclass
class WAFMetrics:
    """WAF performance and security metrics."""

    requests_total: int = 0
    requests_blocked: int = 0
    requests_allowed: int = 0

    # By attack type
    sql_injection_blocked: int = 0
    xss_blocked: int = 0
    rce_blocked: int = 0
    other_blocked: int = 0

    # Performance
    avg_processing_time: float = 0.0
    total_processing_time: float = 0.0

    # Rules
    rules_loaded: int = 0
    rules_executed: int = 0

class WAFMonitor:
    """Monitor WAF operations."""

    def __init__(self):
        self.metrics = WAFMetrics()
        self.start_time = time.time()

    def record_request(self, tx, processing_time: float):
        """Record request metrics."""
        self.metrics.requests_total += 1
        self.metrics.total_processing_time += processing_time
        self.metrics.avg_processing_time = (
            self.metrics.total_processing_time / self.metrics.requests_total
        )

        if tx.interruption:
            self.metrics.requests_blocked += 1

            # Categorize by rule ID
            rule_id = tx.interruption.get("rule_id", 0)
            if 942000 <= rule_id < 943000:
                self.metrics.sql_injection_blocked += 1
            elif 941000 <= rule_id < 942000:
                self.metrics.xss_blocked += 1
            elif 932000 <= rule_id < 933000:
                self.metrics.rce_blocked += 1
            else:
                self.metrics.other_blocked += 1
        else:
            self.metrics.requests_allowed += 1

    def get_stats(self) -> Dict:
        """Get current statistics."""
        uptime = time.time() - self.start_time

        return {
            "uptime_seconds": uptime,
            "requests": {
                "total": self.metrics.requests_total,
                "allowed": self.metrics.requests_allowed,
                "blocked": self.metrics.requests_blocked,
                "block_rate": (
                    self.metrics.requests_blocked / self.metrics.requests_total
                    if self.metrics.requests_total > 0 else 0
                ),
            },
            "attacks_blocked": {
                "sql_injection": self.metrics.sql_injection_blocked,
                "xss": self.metrics.xss_blocked,
                "rce": self.metrics.rce_blocked,
                "other": self.metrics.other_blocked,
            },
            "performance": {
                "avg_processing_ms": self.metrics.avg_processing_time * 1000,
                "requests_per_second": (
                    self.metrics.requests_total / uptime if uptime > 0 else 0
                ),
            },
            "rules": {
                "loaded": self.metrics.rules_loaded,
                "executed": self.metrics.rules_executed,
            },
        }

# Global monitor
waf_monitor = WAFMonitor()
```

### Metrics Endpoint

```python
"""Expose metrics for monitoring."""
from starlette.responses import JSONResponse

async def metrics_endpoint(request):
    """Prometheus-style metrics endpoint."""
    stats = waf_monitor.get_stats()

    # Prometheus format
    metrics_text = f"""
# HELP lewaf_requests_total Total requests processed
# TYPE lewaf_requests_total counter
lewaf_requests_total {stats['requests']['total']}

# HELP lewaf_requests_blocked Requests blocked by WAF
# TYPE lewaf_requests_blocked counter
lewaf_requests_blocked {stats['requests']['blocked']}

# HELP lewaf_requests_allowed Requests allowed by WAF
# TYPE lewaf_requests_allowed counter
lewaf_requests_allowed {stats['requests']['allowed']}

# HELP lewaf_processing_time_seconds Average processing time
# TYPE lewaf_processing_time_seconds gauge
lewaf_processing_time_seconds {stats['performance']['avg_processing_ms'] / 1000}

# HELP lewaf_sql_injection_blocked SQL injection attacks blocked
# TYPE lewaf_sql_injection_blocked counter
lewaf_sql_injection_blocked {stats['attacks_blocked']['sql_injection']}

# HELP lewaf_xss_blocked XSS attacks blocked
# TYPE lewaf_xss_blocked counter
lewaf_xss_blocked {stats['attacks_blocked']['xss']}
"""

    return JSONResponse(content=stats)

# Add to routes
app.add_route("/metrics", metrics_endpoint)
```

---

## Performance Tuning

### Rule Optimization

```python
"""Optimize rule loading and execution."""

# 1. Load rules once at startup (not per request)
waf = WAF(config)
parser = SecLangParser(waf)
parser.from_file("coraza.conf")  # Load once

# 2. Use rule caching
WAF_CONFIG["regex_cache_size"] = 256  # Increase cache

# 3. Disable unnecessary rules
parser.from_string('''
# Disable specific rules if not needed
SecRuleRemoveById 920100  # Example: disable specific rule
''')
```

### Connection Pooling

```python
"""Use connection pooling for external lookups."""
import aiohttp

class RBLCache:
    """Cache RBL lookups to avoid DNS overhead."""

    def __init__(self, ttl=3600):
        self.cache = {}
        self.ttl = ttl

    def get(self, ip):
        """Get cached result."""
        if ip in self.cache:
            result, timestamp = self.cache[ip]
            if time.time() - timestamp < self.ttl:
                return result
        return None

    def set(self, ip, result):
        """Cache result."""
        self.cache[ip] = (result, time.time())
```

### Memory Management

```python
"""Monitor and optimize memory usage."""
import psutil
import gc

def monitor_memory():
    """Monitor memory usage."""
    process = psutil.Process()
    memory_info = process.memory_info()

    return {
        "rss_mb": memory_info.rss / 1024 / 1024,
        "vms_mb": memory_info.vms / 1024 / 1024,
    }

# Periodic cleanup
def cleanup():
    """Periodic memory cleanup."""
    gc.collect()
```

---

## Security Hardening

### Production Security Checklist

- [ ] Run as non-root user
- [ ] Use HTTPS/TLS for all traffic
- [ ] Enable audit logging
- [ ] Set up log rotation
- [ ] Monitor failed requests
- [ ] Implement rate limiting
- [ ] Use secrets management (not hardcoded)
- [ ] Enable security headers
- [ ] Set up alerting for attacks
- [ ] Regular rule updates

### Systemd Service

```ini
# /etc/systemd/system/lewaf.service

[Unit]
Description=LeWAF Protected Application
After=network.target

[Service]
Type=simple
User=lewaf
Group=lewaf
WorkingDirectory=/opt/lewaf
Environment="PATH=/opt/lewaf/.venv/bin"
ExecStart=/opt/lewaf/.venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/lewaf

# Restart
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl enable lewaf
sudo systemctl start lewaf
sudo systemctl status lewaf
```

---

## Troubleshooting

### Common Issues

#### Issue 1: Rules Not Loading

**Symptoms**: 0 rules loaded, no blocking

**Solution**:
```python
# Check file path
import os
print(os.path.exists("coraza.conf"))  # Should be True

# Check for errors
parser = SecLangParser(waf)
try:
    parser.from_file("coraza.conf")
except Exception as e:
    print(f"Error: {e}")

# Verify rules
print(f"Rules loaded: {sum(len(r) for r in waf.rule_group.rules_by_phase.values())}")
```

#### Issue 2: High False Positives

**Symptoms**: Legitimate requests blocked

**Solution**:
```python
# Start in detection mode
WAF_CONFIG["engine"] = "DetectionOnly"

# Review logs to identify problematic rules
# Disable specific rules causing false positives
parser.from_string('''
SecRuleRemoveById 920100  # Disable specific rule
''')
```

#### Issue 3: Performance Issues

**Symptoms**: Slow response times

**Solution**:
```python
# Profile rule execution
import time

start = time.time()
waf.evaluate_rules(tx, phase=1)
duration = time.time() - start
print(f"Phase 1 took {duration*1000:.2f}ms")

# Optimize:
# 1. Increase regex cache
# 2. Disable unused rules
# 3. Use rule markers for early exit
```

### Debug Mode

```python
"""Enable debug logging."""
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("lewaf")
logger.setLevel(logging.DEBUG)

# Now you'll see detailed rule evaluation
```

### Health Check Endpoint

```python
"""Health check for monitoring."""
async def health_check(request):
    """Check WAF health."""
    try:
        # Check rules loaded
        total_rules = sum(
            len(rules) for rules in waf.rule_group.rules_by_phase.values()
        )

        if total_rules == 0:
            return JSONResponse(
                {"status": "unhealthy", "reason": "No rules loaded"},
                status_code=503
            )

        return JSONResponse({
            "status": "healthy",
            "rules_loaded": total_rules,
            "uptime": time.time() - start_time,
        })
    except Exception as e:
        return JSONResponse(
            {"status": "unhealthy", "error": str(e)},
            status_code=503
        )

app.add_route("/health", health_check)
```

---

## Production Deployment Checklist

### Pre-Deployment

- [ ] All tests passing (`uv run pytest`)
- [ ] Rules loaded successfully (594 rules)
- [ ] Configuration validated
- [ ] Logging configured
- [ ] Monitoring setup
- [ ] Health checks working

### Deployment

- [ ] Deploy to staging first
- [ ] Test with staging traffic
- [ ] Review detection logs
- [ ] Tune false positives
- [ ] Enable blocking mode
- [ ] Deploy to production
- [ ] Monitor metrics

### Post-Deployment

- [ ] Monitor block rate
- [ ] Check for false positives
- [ ] Review audit logs
- [ ] Tune rules as needed
- [ ] Set up alerts
- [ ] Document incidents

---

## Next Steps

1. **Review** this guide completely
2. **Test** in staging environment
3. **Monitor** detection rates
4. **Tune** for your traffic patterns
5. **Deploy** to production with confidence

---

**Support**: See PROJECT_STATUS.md for comprehensive documentation
**Issues**: https://github.com/yourorg/lewaf/issues
