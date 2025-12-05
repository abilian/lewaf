# Security Hardening Guide

This guide covers security best practices for deploying LeWAF in production environments.

## Configuration Hardening

### Rule Engine Settings

```python
from lewaf.integration import WAF

waf = WAF({
    "rules": [...],
    "settings": {
        # Reject requests with protocol violations
        "strict_mode": True,
        # Maximum request body size (bytes)
        "request_body_limit": 13107200,  # 12.5 MB
        # Maximum number of arguments
        "argument_limit": 1000,
        # Maximum argument name length
        "argument_name_length_limit": 100,
        # Maximum argument value length
        "argument_value_length_limit": 4000,
    }
})
```

### Recommended CRS Settings

When using OWASP Core Rule Set, configure paranoia level based on your security needs:

```python
# Paranoia Level 1 (Default) - Low false positives
# Paranoia Level 2 - Moderate protection
# Paranoia Level 3 - High protection
# Paranoia Level 4 - Maximum protection (may require tuning)

waf_config = {
    "rules": [
        'SecAction "id:900000,phase:1,pass,setvar:tx.paranoia_level=2"',
        # ... CRS rules
    ]
}
```

## Data Protection

### Sensitive Data Masking

LeWAF automatically masks sensitive data in logs for compliance:

```python
from lewaf.logging.masking import DataMasker

masker = DataMasker({
    "credit_card": True,   # PCI-DSS: Mask all but last 4 digits
    "ssn": True,           # Mask Social Security Numbers
    "password": True,      # Never log passwords
    "auth_token": True,    # Mask authentication tokens
    "email": False,        # Optional: mask email addresses
    "ip_address": False,   # Optional: GDPR IP anonymization
})
```

### PCI-DSS Compliance

For PCI-DSS compliance, ensure:

1. **Credit card masking** is enabled (default)
2. **Audit logging** captures all security events
3. **Log retention** meets compliance requirements (typically 1 year)

```python
from lewaf.logging.audit import AuditLogger

audit = AuditLogger(
    log_file="/var/log/lewaf/audit.log",
    mask_sensitive_data=True,
    retention_days=365,
)
```

### GDPR Compliance

For GDPR compliance:

```python
masker = DataMasker({
    "ip_address": True,    # Anonymize IP addresses
    "email": True,         # Mask email addresses
})
```

## Network Security

### Request Size Limits

Prevent resource exhaustion attacks:

```python
waf_config = {
    "settings": {
        "request_body_limit": 13107200,      # 12.5 MB max body
        "request_body_no_files_limit": 131072,  # 128 KB without files
    }
}
```

### Rate Limiting

Use persistent storage for rate limiting:

```python
from lewaf.storage import RedisStorage

storage = RedisStorage(
    host="localhost",
    port=6379,
    prefix="lewaf:",
    ttl=3600,  # 1 hour window
)

# Rate limiting rule
rules = [
    # Track requests per IP
    'SecRule REMOTE_ADDR "@rx .*" "id:1,phase:1,pass,initcol:ip=%{REMOTE_ADDR}"',
    # Increment counter
    'SecRule REMOTE_ADDR "@rx .*" "id:2,phase:1,pass,setvar:ip.request_count=+1"',
    # Block if over limit (100 requests per hour)
    'SecRule IP:REQUEST_COUNT "@gt 100" "id:3,phase:1,deny,status:429,msg:\'Rate limit exceeded\'"',
]
```

## Deployment Security

### Environment Variables

Never hardcode secrets. Use environment variables:

```python
import os

waf_config = {
    "redis": {
        "host": os.environ.get("REDIS_HOST", "localhost"),
        "password": os.environ.get("REDIS_PASSWORD"),
    }
}
```

### Docker Security

```dockerfile
# Use non-root user
FROM python:3.12-slim
RUN useradd -m -u 1000 lewaf
USER lewaf

# Read-only filesystem where possible
# Mount config as read-only volume
```

### Kubernetes Security

```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    readOnlyRootFilesystem: true
  containers:
  - name: lewaf
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
```

## Logging Security

### Secure Log Storage

1. **Encrypt logs at rest** using filesystem encryption
2. **Restrict log access** to authorized personnel only
3. **Use centralized logging** (ELK, Splunk, etc.) with TLS

### Log Sanitization

LeWAF sanitizes logs by default, but verify:

```python
from lewaf.logging.audit import AuditLogger

# Verify masking is working
audit = AuditLogger(mask_sensitive_data=True)
audit.log_request(request_data)

# Check logs don't contain raw sensitive data
```

## Monitoring and Alerting

### Security Events to Monitor

1. **High volume of blocked requests** - Potential attack
2. **New attack patterns** - Zero-day attempts
3. **Configuration changes** - Unauthorized modifications
4. **Error rate spikes** - System issues

See [Monitoring Guide](../monitoring/prometheus.md) for metrics setup.

## Regular Maintenance

### Rule Updates

Keep CRS rules updated:

```bash
# Check for CRS updates monthly
git -C /path/to/crs pull origin main

# Test rules in staging before production
uv run pytest tests/
```

### Security Audits

1. **Review blocked requests weekly** for false positives
2. **Audit configuration monthly** for drift
3. **Penetration testing quarterly** to validate protection

## Checklist

- [ ] Sensitive data masking enabled
- [ ] Request size limits configured
- [ ] Rate limiting implemented
- [ ] Non-root container user
- [ ] Logs encrypted and access-controlled
- [ ] Monitoring and alerting configured
- [ ] CRS rules up to date
- [ ] Regular security audits scheduled

## Related Documentation

- [Deployment Guide](../deployment/guide.md)
- [Monitoring Guide](../monitoring/prometheus.md)
- [Troubleshooting](../troubleshooting/runbook.md)
