# LeWAF Production Scripts

This directory contains utility scripts for deploying, monitoring, and testing LeWAF in production environments.

## Scripts Overview

### 1. deploy.sh

**Purpose**: Complete deployment automation for LeWAF.

**Features**:
- Environment validation (dev/staging/production)
- Pre-deployment checks (requirements, tests, rules)
- Docker image building
- Health check verification
- Optional monitoring stack (Prometheus/Grafana)
- Production deployment confirmation

**Usage**:
```bash
# Deploy to production
./deploy.sh production

# Deploy to staging
./deploy.sh staging

# Deploy to development
./deploy.sh development
```

**What it does**:
1. Checks for required tools (docker, docker-compose, curl)
2. Validates environment
3. Builds Docker images
4. Runs full test suite (393 tests)
5. Verifies CRS rules load correctly (594 rules)
6. Deploys containers with health checks
7. Starts monitoring stack (production only)
8. Shows deployment status

**Requirements**:
- Docker and Docker Compose
- curl
- Root directory: `/path/to/lewaf`

---

### 2. health_check.sh

**Purpose**: Comprehensive health checking for deployed LeWAF instances.

**Features**:
- Health endpoint validation
- Homepage accessibility check
- WAF blocking verification
- Metrics endpoint check
- Response time measurement

**Usage**:
```bash
# Check local deployment
./health_check.sh

# Check remote deployment
./health_check.sh http://example.com
```

**Checks performed**:
1. **Health endpoint**: Validates `/health` returns 200 with "healthy" status
2. **Homepage**: Ensures `/` is accessible
3. **WAF blocking**: Tests with SQL injection (expects 403 or 200)
4. **Metrics**: Verifies `/metrics` endpoint
5. **Response time**: Measures latency (warns if >1000ms)

**Example output**:
```
[INFO] LeWAF Health Check
==================
[INFO] Target: http://localhost:8000

[INFO] ✓ Health check passed
[INFO]   Status: healthy
[INFO]   Uptime: 123.45s

[INFO] ✓ Homepage accessible
[INFO] ✓ WAF is blocking malicious requests (mode: On)
[INFO] ✓ Metrics endpoint accessible
[INFO] ✓ Response time: 45ms

[INFO] All checks passed! ✓
```

---

### 3. verify_rules.sh

**Purpose**: Verify CRS rules are loaded and functioning correctly.

**Features**:
- Configuration file validation
- Include directive verification
- Rule parsing validation
- Rule matching tests

**Usage**:
```bash
# Verify default configuration
./verify_rules.sh

# Verify specific configuration
./verify_rules.sh /path/to/custom.conf
```

**What it checks**:
1. **Config file exists**: Validates coraza.conf or specified file
2. **Include directives**: Counts and verifies included files exist
3. **Rule parsing**: Loads all rules through LeWAF parser
4. **Rule statistics**: Shows counts by type and phase
5. **Rule matching**: Tests SQL injection, XSS, and clean requests

**Example output**:
```
[INFO] LeWAF Rule Verification
=======================

[INFO] Configuration file: /app/coraza.conf
[INFO] Found 3 Include directives
[INFO] ✓ All included files exist

[INFO] Successfully loaded 594 rules
  SecRule:   572
  SecAction: 15
  SecMarker: 7

Rules by phase:
  Phase 1: 145
  Phase 2: 312
  Phase 3: 85
  Phase 4: 30

[INFO] Testing rule matching...
  ✓ SQL Injection
  ✓ XSS Attack
  ✓ Clean Request

Passed: 3/3

[INFO] All verifications passed! ✓
```

---

### 4. load_test.sh

**Purpose**: Performance and load testing for LeWAF deployments.

**Features**:
- Apache Bench integration
- Clean request load testing
- Malicious request load testing
- Stress testing with increasing load
- Performance analysis

**Usage**:
```bash
# Default: 1000 requests, 10 concurrent
./load_test.sh

# Custom target
./load_test.sh http://example.com

# Custom load: 5000 requests, 50 concurrent
./load_test.sh http://example.com 5000 50
```

**Tests performed**:
1. **Load test**: High volume of clean requests
2. **Malicious load test**: SQL injection and XSS under load
3. **Stress test**: Gradually increase concurrency (10→25→50→100)
4. **Performance analysis**: Req/sec, time/request, failures

**Example output**:
```
[INFO] Running load test...
  URL: http://localhost:8000
  Total requests: 1000
  Concurrency: 10

Completed 1000 requests
Requests per second:    523.45 [#/sec]
Time per request:       19.103 [ms]
Failed requests:        0

[INFO] Summary:
  Requests/sec:    523.45
  Time/request:    19.103ms
  Failed requests: 0

[INFO] ✓ Good throughput (>100 req/s)
[INFO] ✓ Good response time (<100ms)
[INFO] ✓ No failed requests

[INFO] Running stress test...
  Concurrency 10:  523 req/s, 0 failures
  Concurrency 25:  612 req/s, 0 failures
  Concurrency 50:  645 req/s, 0 failures
  Concurrency 100: 658 req/s, 0 failures
```

**Requirements**:
- Apache Bench (`ab`)
  - Ubuntu/Debian: `apt-get install apache2-utils`
  - macOS: `brew install apache2`

---

## Common Workflows

### Initial Deployment

```bash
# 1. Deploy to staging first
cd /path/to/lewaf/examples/production/scripts
./deploy.sh staging

# 2. Verify deployment
./health_check.sh

# 3. Verify rules loaded
./verify_rules.sh

# 4. Run load test
./load_test.sh

# 5. If all good, deploy to production
./deploy.sh production
```

### Health Monitoring

```bash
# Add to cron for periodic health checks
*/5 * * * * /path/to/scripts/health_check.sh || mail -s "LeWAF Down" admin@example.com
```

### Performance Testing

```bash
# Before major changes
./load_test.sh > baseline.log

# After changes
./load_test.sh > current.log

# Compare results
diff baseline.log current.log
```

### Rule Updates

```bash
# After updating CRS rules
./verify_rules.sh

# Test with load
./load_test.sh
```

---

## Continuous Integration

### Example GitHub Actions

```yaml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run tests
        run: cd examples/production/scripts && ./deploy.sh production

      - name: Health check
        run: ./scripts/health_check.sh

      - name: Verify rules
        run: ./scripts/verify_rules.sh
```

---

## Troubleshooting

### deploy.sh fails

```bash
# Check Docker is running
docker ps

# Check docker-compose
docker-compose --version

# Check for port conflicts
lsof -i :8000
```

### health_check.sh fails

```bash
# Check application logs
docker-compose logs lewaf-app

# Check container status
docker-compose ps

# Try manual curl
curl -v http://localhost:8000/health
```

### verify_rules.sh fails

```bash
# Check file exists
ls -la /path/to/coraza.conf

# Check included files
grep "^Include" coraza.conf

# Try manual parsing
cd /path/to/lewaf
uv run python -c "from lewaf.parser import parse_config_file; print(len(parse_config_file('coraza.conf')))"
```

### load_test.sh fails

```bash
# Install Apache Bench
# Ubuntu/Debian:
sudo apt-get install apache2-utils

# macOS:
brew install apache2

# Verify installation
ab -V
```

---

## Performance Benchmarks

### Expected Performance

With CRS rules loaded (594 rules):

- **Throughput**: 500-1000 req/s (depends on hardware)
- **Latency**: 10-50ms average
- **Memory**: ~150-200MB
- **CPU**: 1-2 cores under load

### Performance Tuning

If performance is lower than expected:

1. **Increase regex cache**: Set `regex_cache_size: 512` in config
2. **Reduce logging**: Set `debug: false` in production
3. **Optimize Docker**: Increase memory limits
4. **Use production ASGI server**: gunicorn with uvicorn workers
5. **Enable caching**: Add response caching middleware

---

## Security Notes

### Production Checklist

- [ ] Set `engine: "On"` in production config (blocking mode)
- [ ] Configure `audit_log` for security events
- [ ] Restrict `/metrics` endpoint (nginx allow/deny)
- [ ] Enable HTTPS with valid certificates
- [ ] Set security headers (X-Frame-Options, CSP, etc.)
- [ ] Configure rate limiting in nginx
- [ ] Set up log rotation for audit logs
- [ ] Monitor for anomalies (Prometheus alerts)
- [ ] Regular CRS rule updates
- [ ] Backup configurations

### Monitoring Setup

```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Check Grafana
open http://localhost:3000
# Login: admin/admin

# Check metrics
curl http://localhost:8000/metrics
```

---

## Additional Resources

- [Deployment Guide](../../DEPLOYMENT_GUIDE.md) - Full deployment documentation
- [CHANGELOG.md](../../../CHANGELOG.md) - Release history and features
- [OWASP CRS](https://coreruleset.org/) - Core Rule Set documentation
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) - ModSecurity documentation

---

## Support

For issues or questions:
- Check logs: `docker-compose logs lewaf-app`
- Run health check: `./health_check.sh`
- Verify rules: `./verify_rules.sh`
- Test locally: `cd ../.. && uv run pytest`
