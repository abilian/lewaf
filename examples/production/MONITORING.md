# LeWAF Monitoring and Logging Guide

This guide covers comprehensive monitoring and logging setup for LeWAF production deployments.

## Table of Contents

1. [Metrics Collection](#metrics-collection)
2. [Alerting](#alerting)
3. [Log Management](#log-management)
4. [Dashboard Setup](#dashboard-setup)
5. [Log Aggregation](#log-aggregation)
6. [System Service](#system-service)

---

## Metrics Collection

### Prometheus Setup

LeWAF exposes metrics at the `/metrics` endpoint in Prometheus format.

**Available Metrics**:

```
# Request metrics
http_requests_total{method, status, path}         # Counter: Total requests
http_request_duration_seconds{method, path}       # Histogram: Request latency

# WAF metrics
waf_requests_blocked_total{rule_id, attack_type}  # Counter: Blocked requests
waf_rule_matches_total{rule_id, phase}            # Counter: Rule matches
waf_rules_loaded                                  # Gauge: Number of rules loaded
waf_transaction_duration_seconds                  # Histogram: WAF processing time

# System metrics
process_cpu_seconds_total                         # Counter: CPU time
process_resident_memory_bytes                     # Gauge: Memory usage
process_start_time_seconds                        # Gauge: Process start time
process_open_fds                                  # Gauge: Open file descriptors
```

**Configuration**:

The `prometheus.yml` file configures Prometheus to scrape LeWAF:

```yaml
scrape_configs:
  - job_name: 'lewaf'
    static_configs:
      - targets: ['lewaf-app:8000']
    metrics_path: '/metrics'
    scrape_interval: 10s
```

**Start Prometheus**:

```bash
# With Docker Compose
docker-compose up -d prometheus

# Access UI
open http://localhost:9090
```

**Example Queries**:

```promql
# Request rate (requests per second)
rate(http_requests_total[5m])

# Block rate
rate(waf_requests_blocked_total[5m])

# 95th percentile latency
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# Top attack types
topk(10, sum by (attack_type) (rate(waf_rule_matches_total[5m])))

# Memory usage
process_resident_memory_bytes / 1024 / 1024  # MB
```

---

## Alerting

### Alert Rules

The `alert_rules.yml` file defines Prometheus alerts for critical conditions.

**Alert Categories**:

1. **Application Health**:
   - `LeWAFDown` - Application is unreachable
   - `LeWAFHighErrorRate` - High 5xx error rate

2. **WAF Security**:
   - `HighBlockedRequestRate` - Possible attack
   - `WAFRuleLoadFailure` - Rules failed to load
   - `PossibleDDoSAttack` - Unusual request volume
   - `HighSQLInjectionAttempts` - SQL injection attacks
   - `HighXSSAttempts` - XSS attacks

3. **Performance**:
   - `HighResponseTime` - Slow responses
   - `HighMemoryUsage` - Memory leak detection
   - `HighCPUUsage` - CPU saturation

4. **Infrastructure**:
   - `ContainerDown` - Container failure
   - `LowDiskSpace` - Disk space warning

**Alert Configuration**:

```yaml
groups:
  - name: lewaf_alerts
    rules:
      - alert: LeWAFDown
        expr: up{job="lewaf"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "LeWAF is down"
```

**Alertmanager Integration** (optional):

```yaml
# In prometheus.yml
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']
```

**Example Alertmanager config**:

```yaml
# alertmanager.yml
route:
  receiver: 'team-ops'
  group_by: ['alertname', 'severity']
  group_wait: 10s
  group_interval: 5m
  repeat_interval: 3h

receivers:
  - name: 'team-ops'
    email_configs:
      - to: 'ops@example.com'
        from: 'alertmanager@example.com'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/XXX'
        channel: '#alerts'
```

---

## Log Management

### Log Types

LeWAF produces three types of logs:

1. **Application Logs** (`app.log`):
   - General application events
   - Startup/shutdown
   - Configuration changes
   - Errors and warnings

2. **Audit Logs** (`audit-prod.log`):
   - Security events
   - Blocked requests
   - Rule matches
   - Attack detection

3. **Access Logs** (via web server):
   - All HTTP requests
   - Response codes
   - Client IPs

### Log Rotation

**Using logrotate**:

Install the configuration:

```bash
sudo cp logrotate.conf /etc/logrotate.d/lewaf
sudo chmod 644 /etc/logrotate.d/lewaf
```

**Test configuration**:

```bash
# Dry run
sudo logrotate -d /etc/logrotate.d/lewaf

# Force rotation
sudo logrotate -f /etc/logrotate.d/lewaf
```

**Configuration highlights**:

- Application logs: Daily rotation, 30 days retention
- Audit logs: Weekly rotation, 52 weeks retention
- Compression: Enabled with delayed compression
- Permissions: Logs owned by `lewaf` user

### Centralized Logging

**Using rsyslog**:

Install the configuration:

```bash
sudo cp rsyslog.conf /etc/rsyslog.d/50-lewaf.conf
sudo systemctl restart rsyslog
```

**Forwarding options**:

1. **TCP** (reliable):
   ```
   action(type="omfwd"
          Target="logserver.example.com"
          Port="514"
          Protocol="tcp")
   ```

2. **TLS** (secure):
   ```
   action(type="omfwd"
          Target="logserver.example.com"
          Port="6514"
          Protocol="tcp"
          StreamDriver="gtls"
          StreamDriverMode="1")
   ```

3. **Elasticsearch** (via HTTP):
   ```
   action(type="omhttp"
          server="elasticsearch.example.com"
          serverport="9200"
          restpath="lewaf-logs/_doc")
   ```

### Log Aggregation Stack

**ELK Stack** (Elasticsearch, Logstash, Kibana):

```yaml
# docker-compose.yml addition
elasticsearch:
  image: docker.elastic.co/elasticsearch/elasticsearch:8.10.0
  environment:
    - discovery.type=single-node
    - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
  ports:
    - "9200:9200"

logstash:
  image: docker.elastic.co/logstash/logstash:8.10.0
  volumes:
    - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
  depends_on:
    - elasticsearch

kibana:
  image: docker.elastic.co/kibana/kibana:8.10.0
  ports:
    - "5601:5601"
  depends_on:
    - elasticsearch
```

**Logstash configuration**:

```ruby
# logstash.conf
input {
  file {
    path => "/var/log/lewaf/audit-*.log"
    start_position => "beginning"
    tags => ["audit"]
  }
  file {
    path => "/var/log/lewaf/app.log"
    start_position => "beginning"
    tags => ["app"]
  }
}

filter {
  # Parse JSON logs
  json {
    source => "message"
  }

  # Add geoip for client IPs
  if [remote_addr] {
    geoip {
      source => "remote_addr"
    }
  }

  # Extract rule IDs
  if [rule_id] {
    mutate {
      add_field => { "attack_category" => "unknown" }
    }
    if [rule_id] =~ /^94[0-9]/ {
      mutate {
        update => { "attack_category" => "application-attack" }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "lewaf-%{+YYYY.MM.dd}"
  }
}
```

---

## Dashboard Setup

### Grafana Installation

**With Docker Compose**:

```bash
docker-compose up -d grafana
```

**Access**:
- URL: http://localhost:3000
- Default login: admin / admin

### Import Dashboard

1. **Via UI**:
   - Navigate to Dashboards → Import
   - Upload `grafana-dashboard.json`
   - Select Prometheus as data source

2. **Via provisioning**:

```yaml
# docker-compose.yml
grafana:
  volumes:
    - ./grafana-dashboard.json:/etc/grafana/provisioning/dashboards/lewaf.json
    - ./grafana-datasource.yml:/etc/grafana/provisioning/datasources/prometheus.yml
```

```yaml
# grafana-datasource.yml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
```

### Dashboard Panels

The included dashboard provides:

1. **Request Metrics**:
   - Request rate over time
   - Status code distribution
   - Response time percentiles (p50, p95, p99)

2. **WAF Metrics**:
   - Blocked requests rate
   - Rules loaded count
   - Top attack types
   - Top blocked IPs

3. **System Metrics**:
   - CPU usage
   - Memory usage
   - Uptime

4. **Alerts**:
   - Visual alerts for anomalies
   - Integration with Prometheus alerts

### Custom Dashboards

**Create your own panels**:

```json
{
  "title": "Custom Panel",
  "targets": [
    {
      "expr": "your_promql_query",
      "legendFormat": "{{ label }}"
    }
  ]
}
```

**Example queries**:

- Requests by endpoint: `sum by (path) (rate(http_requests_total[5m]))`
- Block rate by rule: `sum by (rule_id) (rate(waf_requests_blocked_total[5m]))`
- Error rate: `rate(http_requests_total{status=~"5.."}[5m])`

---

## System Service

### systemd Setup

For non-Docker deployments, use systemd to manage LeWAF.

**Install service**:

```bash
# Copy service file
sudo cp systemd/lewaf.service /etc/systemd/system/

# Create user
sudo useradd -r -s /bin/false lewaf

# Create directories
sudo mkdir -p /opt/lewaf /var/log/lewaf
sudo chown lewaf:lewaf /opt/lewaf /var/log/lewaf

# Copy application
sudo cp -r /path/to/lewaf/* /opt/lewaf/
sudo chown -R lewaf:lewaf /opt/lewaf

# Reload systemd
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable lewaf
sudo systemctl start lewaf
```

**Manage service**:

```bash
# Start
sudo systemctl start lewaf

# Stop
sudo systemctl stop lewaf

# Restart
sudo systemctl restart lewaf

# Reload (graceful)
sudo systemctl reload lewaf

# Status
sudo systemctl status lewaf

# Logs
sudo journalctl -u lewaf -f
```

**Service features**:

- Automatic restart on failure
- Resource limits (CPU, memory)
- Security hardening (PrivateTmp, NoNewPrivileges)
- Graceful reload support
- Journal logging integration

---

## Monitoring Best Practices

### 1. Set Up Alerts

Configure alerts for:
- Application downtime (critical)
- High error rates (warning)
- Performance degradation (warning)
- Security attacks (critical)

### 2. Monitor Key Metrics

**Golden Signals**:
- **Latency**: p95 response time < 100ms
- **Traffic**: Requests per second trend
- **Errors**: Error rate < 1%
- **Saturation**: CPU < 80%, Memory < 80%

**WAF-Specific**:
- Block rate trends
- Attack type distribution
- Rule effectiveness
- False positive rate

### 3. Log Retention

- **Application logs**: 30 days local, 90 days aggregated
- **Audit logs**: 1 year local, 7 years aggregated
- **Access logs**: 14 days local, 90 days aggregated

### 4. Regular Reviews

- Weekly: Review dashboards for anomalies
- Monthly: Analyze attack patterns
- Quarterly: Tune alert thresholds
- Yearly: Review retention policies

### 5. Security Monitoring

- Monitor for attack campaigns
- Track blocked IP addresses
- Identify false positives
- Correlate with threat intelligence

---

## Troubleshooting

### Metrics Not Appearing

```bash
# Check /metrics endpoint
curl http://localhost:8000/metrics

# Check Prometheus targets
open http://localhost:9090/targets

# Check Prometheus logs
docker-compose logs prometheus
```

### Logs Not Rotating

```bash
# Check logrotate status
sudo cat /var/lib/logrotate/status

# Test manually
sudo logrotate -v -f /etc/logrotate.d/lewaf

# Check permissions
ls -la /var/log/lewaf/
```

### Alerts Not Firing

```bash
# Check alert rules
curl http://localhost:9090/api/v1/rules

# Check alert state
open http://localhost:9090/alerts

# Validate alert expression
# Use Prometheus UI to test query
```

### High Memory Usage

```bash
# Check current usage
docker stats lewaf-app

# Check for memory leaks
# Monitor process_resident_memory_bytes over time

# Increase limit if needed
# Edit docker-compose.yml:
#   mem_limit: 512m
```

---

## Additional Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [Logrotate Manual](https://linux.die.net/man/8/logrotate)
- [Rsyslog Documentation](https://www.rsyslog.com/doc/)
- [systemd Service Management](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
