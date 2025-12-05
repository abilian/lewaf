# LeWAF Docker Examples

This directory contains Docker configuration examples for LeWAF deployment.

## Files

### Dockerfile
**Purpose**: Dockerfile template
**Status**: ⚠️ Template for future use - **Not currently buildable**
**Use Case**: Reference for production deployments when LeWAF is packaged

**Note**: This Dockerfile assumes LeWAF is packaged as a Python wheel and includes a `lewaf.server` module. It's a complete production template but requires:
- Complete `pyproject.toml` with all metadata
- `README.md` file
- Proper package structure
- Entry point module (`lewaf.server`)

**This is intentional** - it's a template showing best practices for when LeWAF is ready for distribution.

### Dockerfile.simple
**Purpose**: Simplified Dockerfile for documentation testing
**Status**: ✅ Working - Use this for testing
**Use Case**: Validate configuration structure and Docker patterns

This Dockerfile validates:
- Configuration file syntax
- Directory structure
- User permissions
- Security settings (non-root user)
- Health check patterns

### docker-compose.yml
**Purpose**: Multi-service Docker Compose configuration
**Status**: ✅ Syntax validated - ready for use when LeWAF is deployed
**Use Case**: Deploy LeWAF with Redis and monitoring stack

Includes:
- LeWAF application service
- Redis for persistent storage
- Prometheus for metrics (optional, profile: monitoring)
- Grafana for dashboards (optional, profile: monitoring)

### Configuration Files

- `lewaf.conf` - Main LeWAF configuration
- `crs-setup.conf` - OWASP CRS configuration
- `prometheus.yml` - Prometheus scrape configuration
- `.dockerignore` - Files to exclude from Docker build

## Testing

### Quick Test (Configuration Structure)

```bash
# Build simplified image
docker build -f Dockerfile.simple -t lewaf:test .

# Verify image built successfully
docker images | grep lewaf
```

### Validate Docker Compose

```bash
# Check syntax
docker-compose config

# Start services (monitoring disabled by default)
docker-compose up -d

# Start with monitoring
docker-compose --profile monitoring up -d

# Check services
docker-compose ps

# Stop services
docker-compose down
```

### Full Production Build

When LeWAF is fully packaged, use the production Dockerfile:

```bash
# Build production image
docker build -f Dockerfile -t lewaf:v1.0.0 .

# Run container
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/lewaf.conf:/app/config/lewaf.conf:ro \
  -v $(pwd)/rules:/app/rules:ro \
  lewaf:v1.0.0

# Check health
curl http://localhost:8000/health
```

## Configuration

### Environment Variables

The following environment variables can be set:

| Variable | Default | Description |
|----------|---------|-------------|
| `LEWAF_CONFIG` | `/app/config/lewaf.conf` | Main config file path |
| `LEWAF_RULES_DIR` | `/app/rules` | Rules directory path |
| `LEWAF_LOG_LEVEL` | `INFO` | Log level |
| `LEWAF_LOG_FORMAT` | `text` | Log format (text, json) |
| `LEWAF_STORAGE_BACKEND` | `memory` | Storage backend (memory, redis) |
| `LEWAF_REDIS_URL` | - | Redis connection URL |

### Volume Mounts

Recommended volumes:

```yaml
volumes:
  # Configuration (read-only)
  - ./lewaf.conf:/app/config/lewaf.conf:ro
  - ./crs-setup.conf:/app/config/crs-setup.conf:ro
  - ./rules:/app/rules:ro

  # Data (read-write)
  - lewaf-data:/app/data
  - lewaf-logs:/app/logs
```

## Security

The Dockerfiles implement security best practices:

- ✅ Non-root user (`lewaf:lewaf`)
- ✅ Read-only root filesystem (in production)
- ✅ Dropped capabilities
- ✅ Security scanning ready
- ✅ Multi-stage build (minimal attack surface)
- ✅ Health checks
- ✅ Resource limits

## Next Steps

1. **Review**: Check the [deployment documentation](../../docs/deployment/docker.md)
2. **Customize**: Adjust configurations for your environment
3. **Test**: Validate with your specific rules and backend
4. **Deploy**: Use in staging before production
5. **Monitor**: Set up Prometheus and Grafana

## Troubleshooting

### Build Fails

- Check Docker version: `docker version`
- Verify base image is accessible: `docker pull python:3.12-slim`
- Check disk space: `df -h`

### Container Won't Start

- Check logs: `docker logs <container-name>`
- Verify configuration: `docker exec <container> cat /app/config/lewaf.conf`
- Check permissions: `docker exec <container> ls -la /app`

### Health Check Fails

- Test manually: `docker exec <container> curl http://localhost:8000/health`
- Check service is running: `docker exec <container> ps aux`
- Review logs for errors

## References

- [Docker Deployment Guide](../../docs/deployment/docker.md)
- [Troubleshooting Runbook](../../docs/troubleshooting/runbook.md)
- [Performance Tuning](../../docs/performance/tuning.md)

---

**Last Updated**: 2025-11-13
**Phase 16**: Production Documentation
