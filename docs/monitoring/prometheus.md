# Monitoring with Prometheus

This guide covers setting up monitoring and metrics collection for LeWAF using Prometheus and Grafana.

## Overview

LeWAF provides structured logging that can be integrated with monitoring systems. This guide shows how to expose metrics for Prometheus scraping.

## Basic Metrics Setup

### Custom Metrics Middleware

Create a middleware that exposes WAF metrics:

```python
import time
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

# Define metrics
REQUEST_COUNT = Counter(
    'lewaf_requests_total',
    'Total requests processed by LeWAF',
    ['method', 'endpoint', 'status']
)

BLOCKED_COUNT = Counter(
    'lewaf_blocked_total',
    'Total requests blocked by LeWAF',
    ['rule_id', 'attack_type']
)

REQUEST_LATENCY = Histogram(
    'lewaf_request_duration_seconds',
    'Request processing duration',
    ['method', 'endpoint'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
)

ACTIVE_TRANSACTIONS = Gauge(
    'lewaf_active_transactions',
    'Number of active WAF transactions'
)

class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start_time = time.time()
        ACTIVE_TRANSACTIONS.inc()

        try:
            response = await call_next(request)

            # Record request metrics
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.url.path,
                status=response.status_code
            ).inc()

            # Record blocked requests (check for WAF block)
            if response.status_code == 403:
                rule_id = response.headers.get('X-WAF-Rule-ID', 'unknown')
                BLOCKED_COUNT.labels(
                    rule_id=rule_id,
                    attack_type=response.headers.get('X-WAF-Attack-Type', 'unknown')
                ).inc()

            return response
        finally:
            ACTIVE_TRANSACTIONS.dec()
            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=request.url.path
            ).observe(time.time() - start_time)
```

### Metrics Endpoint

Add a `/metrics` endpoint for Prometheus:

```python
from fastapi import FastAPI
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

app = FastAPI()

@app.get("/metrics")
async def metrics():
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )
```

## Key Metrics to Track

### Request Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `lewaf_requests_total` | Counter | Total requests processed |
| `lewaf_blocked_total` | Counter | Requests blocked by WAF |
| `lewaf_request_duration_seconds` | Histogram | Processing latency |
| `lewaf_active_transactions` | Gauge | Current active transactions |

### Security Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `lewaf_attacks_detected_total` | Counter | Attacks detected by type |
| `lewaf_rule_matches_total` | Counter | Rule match count by rule ID |
| `lewaf_anomaly_score` | Histogram | Distribution of anomaly scores |

### System Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `lewaf_rule_count` | Gauge | Number of loaded rules |
| `lewaf_cache_hits_total` | Counter | Regex cache hits |
| `lewaf_cache_misses_total` | Counter | Regex cache misses |

## Prometheus Configuration

### prometheus.yml

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'lewaf'
    static_configs:
      - targets: ['lewaf-app:8000']
    metrics_path: /metrics
    scrape_interval: 10s
```

### Docker Compose Setup

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana

volumes:
  grafana-data:
```

## Grafana Dashboards

### WAF Overview Dashboard

Create a dashboard with these panels:

**1. Request Rate**
```promql
rate(lewaf_requests_total[5m])
```

**2. Block Rate**
```promql
rate(lewaf_blocked_total[5m])
```

**3. Block Percentage**
```promql
sum(rate(lewaf_blocked_total[5m])) / sum(rate(lewaf_requests_total[5m])) * 100
```

**4. Latency (p95)**
```promql
histogram_quantile(0.95, rate(lewaf_request_duration_seconds_bucket[5m]))
```

**5. Top Blocked Rules**
```promql
topk(10, sum by (rule_id) (rate(lewaf_blocked_total[1h])))
```

**6. Attack Types**
```promql
sum by (attack_type) (rate(lewaf_blocked_total[5m]))
```

## Alerting Rules

### alerts.yml

```yaml
groups:
  - name: lewaf
    rules:
      # High block rate alert
      - alert: HighBlockRate
        expr: |
          sum(rate(lewaf_blocked_total[5m])) /
          sum(rate(lewaf_requests_total[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High WAF block rate detected"
          description: "Block rate is {{ $value | humanizePercentage }}"

      # Potential attack alert
      - alert: PotentialAttack
        expr: rate(lewaf_blocked_total[1m]) > 100
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Potential attack in progress"
          description: "{{ $value }} requests blocked per second"

      # High latency alert
      - alert: HighWAFLatency
        expr: |
          histogram_quantile(0.95, rate(lewaf_request_duration_seconds_bucket[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High WAF processing latency"
          description: "p95 latency is {{ $value }}s"

      # WAF down alert
      - alert: WAFDown
        expr: up{job="lewaf"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "LeWAF instance is down"
```

## Log-Based Metrics

If you prefer log-based metrics, use structured JSON logging:

```python
from lewaf.logging.audit import AuditLogger
import json

class PrometheusAuditLogger(AuditLogger):
    def log_blocked_request(self, transaction, rule_id, message):
        # Standard audit log
        super().log_blocked_request(transaction, rule_id, message)

        # Also emit metric-friendly log
        metric_log = {
            "metric": "lewaf_blocked",
            "rule_id": rule_id,
            "attack_type": self._classify_attack(rule_id),
            "timestamp": transaction.timestamp.isoformat(),
        }
        print(json.dumps(metric_log))
```

Then use a log processor (Loki, Fluentd) to extract metrics.

## Health Checks

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 5
```

### Health Endpoint

```python
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "rules_loaded": len(waf.rule_group.rules_by_phase),
        "version": "0.7.0",
    }
```

## Best Practices

1. **Use labels wisely** - Too many label values cause cardinality explosion
2. **Set appropriate scrape intervals** - 10-15s for most metrics
3. **Use histograms for latency** - Not summaries, for aggregation
4. **Alert on symptoms** - High latency, high error rate
5. **Dashboard hierarchy** - Overview → Details → Debug

## Related Documentation

- [Security Hardening](../security/hardening.md)
- [Performance Tuning](../performance/tuning.md)
- [Troubleshooting](../troubleshooting/runbook.md)
