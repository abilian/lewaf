# Coraza-Py Reverse Proxy Example

This example demonstrates how to use Coraza-Py as a reverse proxy with WAF protection.

## Architecture

```
Client → Coraza WAF Proxy → Upstream Server
         (Port 8080)        (Backend App)
```

## Quick Start

### 1. Using Docker Compose (Recommended)

Start the example with HTTPBin as the backend:

```bash
cd examples/reverse-proxy
docker-compose up -d
```

This will start:
- **HTTPBin backend** on port 8001 (direct access)
- **Coraza WAF Proxy** on port 8080 (protected access)

### 2. Manual Setup

Install dependencies:
```bash
pip install -e .
```

Start a backend server (e.g., HTTPBin):
```bash
docker run -p 8001:80 httpbin/httpbin
```

Start the Coraza proxy:
```bash
python -m lewaf.proxy.cli --upstream http://localhost:8001 --rules-file examples/reverse-proxy/waf.conf
```

## Testing the WAF

### 1. Normal Requests (Should Pass)

```bash
# Health check
curl http://localhost:8080/health

# Normal request
curl http://localhost:8080/get

# POST request
curl -X POST http://localhost:8080/post -d '{"message": "hello world"}'
```

### 2. Malicious Requests (Should be Blocked)

```bash
# SQL Injection
curl "http://localhost:8080/get?id=1' OR 1=1--"

# XSS Attack
curl "http://localhost:8080/get?search=<script>alert('xss')</script>"

# Command Injection
curl "http://localhost:8080/get?cmd=ls%20-la;cat%20/etc/passwd"

# Path Traversal
curl "http://localhost:8080/get?file=../../../etc/passwd"

# Malicious User-Agent
curl -H "User-Agent: sqlmap/1.0" http://localhost:8080/get
```

Expected response for blocked requests:
```json
{
    "error": "Request blocked by WAF",
    "rule_id": 1001,
    "message": "Request blocked by WAF"
}
```

## Configuration

### WAF Rules (`waf.conf`)

The configuration file uses ModSecurity SecLang syntax:

```
SecRule ARGS "@rx (\bunion\b.*\bselect\b)" \
    "id:1001,phase:2,deny,log,msg:'SQL Injection Attack'"
```

### CLI Options

```bash
python -m lewaf.proxy.cli --help
```

Key options:
- `--upstream`: Backend server URL
- `--rules-file`: Path to WAF rules
- `--host`, `--port`: Proxy binding
- `--timeout`: Upstream timeout
- `--log-level`: Logging verbosity

## Monitoring

### Logs

WAF events are logged with structured information:
```
2025-01-11 10:30:15 - lewaf.integrations.starlette - WARNING - Request blocked in headers phase by rule 1001
```

### Metrics

The proxy exposes a health endpoint:
```bash
curl http://localhost:8080/health
```

Response:
```json
{
    "status": "healthy",
    "upstream": "http://backend:80",
    "proxy": "coraza-py"
}
```

## Performance

The Starlette-based proxy is designed for high performance:

- **Async I/O**: Non-blocking request handling
- **Connection Pooling**: Efficient upstream connections
- **Streaming**: Memory-efficient response handling
- **Configurable Limits**: Connection and timeout controls

## Production Deployment

### Environment Variables

```bash
export UPSTREAM_URL=http://backend:8000
export RULES_FILE=/etc/coraza/waf.conf
export HOST=0.0.0.0
export PORT=8080
export LOG_LEVEL=INFO
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coraza-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: coraza-proxy
  template:
    spec:
      containers:
      - name: coraza-proxy
        image: coraza-py:latest
        command:
          - python
          - -m
          - lewaf.proxy.cli
          - --upstream
          - http://backend-service:80
          - --rules-file
          - /etc/coraza/waf.conf
          - --host
          - 0.0.0.0
          - --port
          - 8080
        volumeMounts:
        - name: waf-config
          mountPath: /etc/coraza
```

## Security Considerations

1. **Fail-Open**: On WAF errors, requests are allowed through
2. **Rate Limiting**: Basic IP-based rate limiting included
3. **SSL Termination**: Consider using a load balancer for HTTPS
4. **Resource Limits**: Configure appropriate memory/CPU limits
5. **Rule Tuning**: Adjust rules based on your application needs
