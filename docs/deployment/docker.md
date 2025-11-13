# Docker Deployment Guide

**LeWAF Production Docker Deployment**

This guide covers deploying LeWAF in production using Docker and Docker Compose.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Volume Mounts](#volume-mounts)
- [Environment Variables](#environment-variables)
- [Health Checks](#health-checks)
- [Security Best Practices](#security-best-practices)
- [Deployment Scenarios](#deployment-scenarios)
- [Troubleshooting](#troubleshooting)
- [Performance Tuning](#performance-tuning)

---

## Overview

LeWAF provides production-ready Docker images optimized for:
- **Small image size** (multi-stage build)
- **Security** (non-root user, minimal dependencies)
- **Performance** (optimized Python runtime)
- **Observability** (health checks, metrics endpoints)

### Image Features

- Base: Python 3.12 slim
- Non-root user (`lewaf:lewaf`)
- Health check included
- Configurable via environment variables
- Volume mounts for configuration and data
- Multi-architecture support (amd64, arm64)

---

## Quick Start

### 1. Build the Image

```bash
cd /path/to/lewaf
docker build -f examples/docker/Dockerfile -t lewaf:latest .
```

### 2. Run Standalone Container

```bash
docker run -d \
  --name lewaf \
  -p 8000:8000 \
  -v $(pwd)/examples/docker/lewaf.conf:/app/config/lewaf.conf:ro \
  -v $(pwd)/examples/docker/rules:/app/rules:ro \
  lewaf:latest
```

### 3. Verify Deployment

```bash
# Check health
curl http://localhost:8000/health

# View logs
docker logs lewaf

# Check container status
docker ps | grep lewaf
```

### 4. Using Docker Compose

```bash
cd examples/docker
docker-compose up -d
```

---

## Configuration

### Configuration Files

LeWAF requires two main configuration files:

#### 1. `lewaf.conf` - Main Configuration

```apache
# Engine settings
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off

# Body limits
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072

# Audit logging
SecAuditEngine RelevantOnly
SecAuditLog /app/logs/audit.log
SecAuditLogFormat JSON

# Include CRS setup
Include /app/config/crs-setup.conf
```

#### 2. `crs-setup.conf` - CRS Configuration

```apache
# Paranoia level (1-4)
SecAction "id:900000,phase:1,nolog,pass,setvar:tx.paranoia_level=1"

# Anomaly scoring thresholds
SecAction "id:900110,phase:1,nolog,pass,\
  setvar:tx.inbound_anomaly_score_threshold=5,\
  setvar:tx.outbound_anomaly_score_threshold=4"
```

### Mounting Configuration

```bash
docker run -d \
  -v /path/to/lewaf.conf:/app/config/lewaf.conf:ro \
  -v /path/to/crs-setup.conf:/app/config/crs-setup.conf:ro \
  -v /path/to/rules:/app/rules:ro \
  lewaf:latest
```

**Note**: Use `:ro` (read-only) for security.

---

## Volume Mounts

### Required Volumes

| Path | Purpose | Read-Only |
|------|---------|-----------|
| `/app/config/lewaf.conf` | Main configuration | Yes |
| `/app/config/crs-setup.conf` | CRS setup | Yes |
| `/app/rules` | Rule files directory | Yes |

### Optional Volumes

| Path | Purpose | Read-Only |
|------|---------|-----------|
| `/app/data` | Persistent storage (collections) | No |
| `/app/logs` | Log files | No |
| `/tmp` | Temporary files | No |

### Docker Compose Example

```yaml
services:
  lewaf:
    image: lewaf:latest
    volumes:
      # Configuration (read-only)
      - ./lewaf.conf:/app/config/lewaf.conf:ro
      - ./crs-setup.conf:/app/config/crs-setup.conf:ro
      - ./rules:/app/rules:ro

      # Persistent data (read-write)
      - lewaf-data:/app/data
      - lewaf-logs:/app/logs

volumes:
  lewaf-data:
  lewaf-logs:
```

### Volume Permissions

The container runs as user `lewaf:lewaf` (UID/GID typically 999).

```bash
# Set correct permissions on host
chown -R 999:999 /path/to/data
chmod 755 /path/to/data
```

---

## Environment Variables

### Core Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LEWAF_CONFIG` | `/app/config/lewaf.conf` | Main config file path |
| `LEWAF_RULES_DIR` | `/app/rules` | Rules directory |
| `LEWAF_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `LEWAF_LOG_FORMAT` | `text` | Log format (text, json) |
| `PYTHONUNBUFFERED` | `1` | Disable Python buffering |

### Storage Backend

| Variable | Default | Description |
|----------|---------|-------------|
| `LEWAF_STORAGE_BACKEND` | `memory` | Backend type (memory, redis) |
| `LEWAF_REDIS_URL` | - | Redis connection URL |
| `LEWAF_REDIS_PREFIX` | `lewaf:` | Redis key prefix |

### Performance

| Variable | Default | Description |
|----------|---------|-------------|
| `LEWAF_WORKERS` | `auto` | Number of worker processes |
| `LEWAF_MAX_CONNECTIONS` | `1000` | Max concurrent connections |
| `LEWAF_TIMEOUT` | `30` | Request timeout (seconds) |

### Example Usage

```bash
docker run -d \
  -e LEWAF_LOG_LEVEL=DEBUG \
  -e LEWAF_LOG_FORMAT=json \
  -e LEWAF_STORAGE_BACKEND=redis \
  -e LEWAF_REDIS_URL=redis://redis:6379/0 \
  -e LEWAF_WORKERS=4 \
  lewaf:latest
```

---

## Health Checks

### Built-in Health Check

The Dockerfile includes a health check:

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1
```

### Health Check Endpoint

```bash
# Check health
curl http://localhost:8000/health

# Expected response (HTTP 200)
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 3600,
  "checks": {
    "engine": "ok",
    "storage": "ok"
  }
}
```

### Custom Health Checks

Override in docker-compose.yml:

```yaml
services:
  lewaf:
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
```

### Monitoring Health Status

```bash
# Check container health
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Health}}"

# Watch health status
watch -n 5 'docker inspect --format="{{.State.Health.Status}}" lewaf'

# Get detailed health logs
docker inspect lewaf | jq '.[0].State.Health'
```

---

## Security Best Practices

### 1. Run as Non-Root User

The Dockerfile already creates a non-root user:

```dockerfile
RUN groupadd -r lewaf && useradd -r -g lewaf lewaf
USER lewaf
```

**Verify**:
```bash
docker exec lewaf whoami
# Output: lewaf
```

### 2. Use Read-Only Mounts

Mount configuration files as read-only:

```yaml
volumes:
  - ./lewaf.conf:/app/config/lewaf.conf:ro
  - ./rules:/app/rules:ro
```

### 3. Enable Read-Only Root Filesystem

```yaml
services:
  lewaf:
    read_only: true
    tmpfs:
      - /tmp
      - /app/logs
```

### 4. Drop Capabilities

```yaml
services:
  lewaf:
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Only if binding to port < 1024
```

### 5. Use Secrets for Sensitive Data

```yaml
services:
  lewaf:
    secrets:
      - redis_password
    environment:
      - LEWAF_REDIS_PASSWORD_FILE=/run/secrets/redis_password

secrets:
  redis_password:
    file: ./secrets/redis_password.txt
```

### 6. Scan Images for Vulnerabilities

```bash
# Using Trivy
trivy image lewaf:latest

# Using Docker Scout
docker scout cves lewaf:latest

# Using Snyk
snyk container test lewaf:latest
```

### 7. Use Specific Image Tags

```yaml
# Bad - uses latest
image: lewaf:latest

# Good - uses specific version
image: lewaf:1.0.0
```

### 8. Limit Resources

```yaml
services:
  lewaf:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
```

### 9. Network Isolation

```yaml
services:
  lewaf:
    networks:
      - frontend  # Exposed to internet
      - backend   # Access to Redis

networks:
  frontend:
    driver: bridge
  backend:
    internal: true  # No internet access
```

### 10. Enable Logging

```yaml
services:
  lewaf:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

---

## Deployment Scenarios

### Scenario 1: Standalone Deployment

**Use Case**: Development, testing, small deployments

```yaml
version: '3.8'

services:
  lewaf:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./lewaf.conf:/app/config/lewaf.conf:ro
      - ./rules:/app/rules:ro
    restart: unless-stopped
```

**Start**:
```bash
docker-compose up -d
```

### Scenario 2: With Redis for Persistent Storage

**Use Case**: Production with persistent collections

```yaml
version: '3.8'

services:
  lewaf:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./lewaf.conf:/app/config/lewaf.conf:ro
      - ./rules:/app/rules:ro
    environment:
      - LEWAF_STORAGE_BACKEND=redis
      - LEWAF_REDIS_URL=redis://redis:6379/0
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes
    restart: unless-stopped

volumes:
  redis-data:
```

**Start**:
```bash
docker-compose up -d
```

### Scenario 3: With Monitoring (Prometheus + Grafana)

**Use Case**: Production with full observability

```bash
# Start with monitoring profile
docker-compose --profile monitoring up -d

# Access services
# LeWAF: http://localhost:8000
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/admin)
```

See `examples/docker/docker-compose.yml` for full configuration.

### Scenario 4: Behind Reverse Proxy (Nginx)

**nginx.conf**:
```nginx
upstream lewaf_backend {
    server lewaf:8000;
}

server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://lewaf_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**docker-compose.yml**:
```yaml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - lewaf

  lewaf:
    build: .
    expose:
      - "8000"
```

### Scenario 5: Multi-Instance Load Balanced

**Use Case**: High-traffic production

```yaml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - lewaf

  lewaf:
    build: .
    expose:
      - "8000"
    environment:
      - LEWAF_STORAGE_BACKEND=redis
      - LEWAF_REDIS_URL=redis://redis:6379/0
    deploy:
      replicas: 3  # Run 3 instances

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data

volumes:
  redis-data:
```

---

## Troubleshooting

### Container Won't Start

**Check logs**:
```bash
docker logs lewaf
docker logs --tail 50 lewaf
docker logs -f lewaf  # Follow logs
```

**Common issues**:

1. **Configuration file not found**
   ```
   Error: Config file not found: /app/config/lewaf.conf
   ```
   **Fix**: Verify volume mount path
   ```bash
   docker run -v $(pwd)/lewaf.conf:/app/config/lewaf.conf:ro ...
   ```

2. **Permission denied**
   ```
   PermissionError: [Errno 13] Permission denied: '/app/data'
   ```
   **Fix**: Set correct permissions
   ```bash
   chmod 755 /path/to/data
   chown -R 999:999 /path/to/data
   ```

3. **Port already in use**
   ```
   Error: bind: address already in use
   ```
   **Fix**: Change port mapping
   ```bash
   docker run -p 8080:8000 ...
   ```

### Health Check Failing

```bash
# Check health status
docker inspect lewaf | jq '.[0].State.Health'

# Test health endpoint manually
docker exec lewaf curl -f http://localhost:8000/health
```

**Common causes**:
- Application not fully started (wait longer, increase `start_period`)
- Wrong health check port
- Application crashed (check logs)

### High Memory Usage

```bash
# Check memory usage
docker stats lewaf

# Limit memory
docker run -m 2G lewaf:latest
```

### Connection Issues

**Test connectivity**:
```bash
# From host
curl http://localhost:8000/health

# From another container
docker exec other-container curl http://lewaf:8000/health

# Check network
docker network inspect lewaf-network
```

### Redis Connection Failed

```bash
# Check Redis is running
docker ps | grep redis

# Test Redis connection
docker exec lewaf ping redis -c 1

# Check Redis logs
docker logs lewaf-redis
```

---

## Performance Tuning

### 1. Worker Processes

```yaml
environment:
  - LEWAF_WORKERS=4  # Set to number of CPU cores
```

**Calculate optimal workers**:
```bash
# On host
nproc

# Set workers = CPU cores
```

### 2. Resource Limits

```yaml
deploy:
  resources:
    limits:
      cpus: '4'
      memory: 4G
    reservations:
      cpus: '1'
      memory: 1G
```

### 3. Connection Pooling

```yaml
environment:
  - LEWAF_MAX_CONNECTIONS=2000
  - LEWAF_KEEPALIVE_TIMEOUT=65
```

### 4. Redis Tuning

```yaml
services:
  redis:
    command: >
      redis-server
      --maxmemory 2gb
      --maxmemory-policy allkeys-lru
      --tcp-backlog 511
      --timeout 0
      --tcp-keepalive 300
```

### 5. Logging Optimization

**For high-traffic environments**:

```yaml
environment:
  - LEWAF_LOG_LEVEL=WARNING  # Reduce logging
  - LEWAF_AUDIT_LOG=off      # Disable audit logs
```

**Use external logging**:
```yaml
logging:
  driver: "syslog"
  options:
    syslog-address: "udp://logserver:514"
```

### 6. Volume Performance

**Use tmpfs for temporary files**:
```yaml
tmpfs:
  - /tmp:size=1G,mode=1777
```

**Use volumes instead of bind mounts** for better performance.

### 7. Network Performance

```yaml
networks:
  lewaf-network:
    driver: bridge
    driver_opts:
      com.docker.network.driver.mtu: 1500
```

### 8. Disable Unnecessary Features

```apache
# In lewaf.conf
SecResponseBodyAccess Off  # Don't inspect responses
SecUploadKeepFiles Off     # Don't keep uploaded files
```

### 9. Rule Optimization

- Remove unused rules
- Adjust paranoia level based on needs
- Use rule exclusions for known false positives

### 10. Monitoring

```yaml
# Add Prometheus metrics
environment:
  - LEWAF_METRICS_ENABLED=true
  - LEWAF_METRICS_PORT=9090
```

**Monitor key metrics**:
- Request rate
- Latency (p50, p95, p99)
- Memory usage
- CPU usage
- Rule evaluation time

---

## Next Steps

- **Kubernetes Deployment**: See [kubernetes.md](kubernetes.md)
- **Performance Guide**: See [../performance/tuning.md](../performance/tuning.md)
- **Security Hardening**: See [../security/hardening.md](../security/hardening.md)
- **Monitoring Setup**: See [../monitoring/prometheus.md](../monitoring/prometheus.md)

---

**Questions or Issues?**
- GitHub Issues: https://github.com/yourorg/lewaf/issues
- Documentation: https://lewaf.readthedocs.io
