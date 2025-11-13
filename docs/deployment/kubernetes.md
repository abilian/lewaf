# Kubernetes Deployment Guide

**LeWAF Production Kubernetes Deployment**

This guide covers deploying LeWAF on Kubernetes with production-grade configuration, high availability, and auto-scaling.

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Deployment Options](#deployment-options)
- [High Availability](#high-availability)
- [Auto-Scaling](#auto-scaling)
- [Security](#security)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

---

## Overview

LeWAF is deployed on Kubernetes using:
- **Deployment** for pod management
- **Service** for internal load balancing
- **Ingress** for external access
- **HorizontalPodAutoscaler** for auto-scaling
- **ConfigMap** for configuration
- **Secret** for sensitive data
- **PodDisruptionBudget** for high availability

### Key Features

- Production-ready security (non-root, read-only filesystem)
- Liveness, readiness, and startup probes
- Resource limits and requests
- Horizontal pod autoscaling
- Rolling updates with zero downtime
- Pod anti-affinity for distribution
- Integration with Prometheus metrics

---

## Prerequisites

### Required

1. **Kubernetes Cluster** (v1.24+)
   ```bash
   kubectl version --short
   ```

2. **kubectl** CLI tool
   ```bash
   kubectl version --client
   ```

3. **Container Registry** (Docker Hub, GCR, ECR, etc.)

### Optional

4. **Kustomize** (included in kubectl 1.14+)
   ```bash
   kubectl kustomize --help
   ```

5. **Helm** (v3+) for chart-based deployment
   ```bash
   helm version
   ```

6. **Ingress Controller** (Nginx, AWS ALB, etc.)
   ```bash
   kubectl get ingressclass
   ```

7. **Metrics Server** for HPA
   ```bash
   kubectl get deployment metrics-server -n kube-system
   ```

---

## Quick Start

### 1. Build and Push Image

```bash
# Build image
docker build -f examples/docker/Dockerfile -t lewaf:latest .

# Tag for registry
docker tag lewaf:latest your-registry/lewaf:v1.0.0

# Push to registry
docker push your-registry/lewaf:v1.0.0
```

### 2. Deploy Using kubectl

```bash
# Navigate to manifests directory
cd examples/kubernetes/base

# Deploy all resources
kubectl apply -f namespace.yaml
kubectl apply -f serviceaccount.yaml
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f hpa.yaml
kubectl apply -f pdb.yaml
kubectl apply -f ingress.yaml
```

### 3. Deploy Using Kustomize

```bash
# Deploy base configuration
kubectl apply -k examples/kubernetes/base

# Or deploy production overlay
kubectl apply -k examples/kubernetes/overlays/production
```

### 4. Verify Deployment

```bash
# Check namespace
kubectl get ns lewaf

# Check all resources
kubectl get all -n lewaf

# Check pod status
kubectl get pods -n lewaf -o wide

# Check logs
kubectl logs -n lewaf -l app=lewaf --tail=50
```

### 5. Test the Deployment

```bash
# Port forward for local testing
kubectl port-forward -n lewaf svc/lewaf 8000:80

# Test health endpoint
curl http://localhost:8000/health

# Expected output
{"status": "healthy", "version": "1.0.0"}
```

---

## Architecture

### Resource Overview

```
┌─────────────────────────────────────────────┐
│              Kubernetes Cluster              │
├─────────────────────────────────────────────┤
│                                             │
│  ┌────────────┐       ┌───────────────┐   │
│  │  Ingress   │──────▶│   Service     │   │
│  └────────────┘       └───────┬───────┘   │
│                               │            │
│       ┌───────────────────────┼────────┐  │
│       │                       │        │  │
│  ┌────▼────┐  ┌──────▼──────┐  ┌────▼─┐ │
│  │  Pod 1  │  │    Pod 2    │  │ Pod 3│ │
│  │ (LeWAF) │  │   (LeWAF)   │  │(LeWAF│ │
│  └─────────┘  └─────────────┘  └──────┘ │
│                                             │
│  ┌──────────────────────────────────────┐ │
│  │     HorizontalPodAutoscaler          │ │
│  │  (Scales pods based on CPU/Memory)   │ │
│  └──────────────────────────────────────┘ │
│                                             │
│  ┌──────────────────────────────────────┐ │
│  │      PodDisruptionBudget             │ │
│  │  (Ensures min 2 pods during updates) │ │
│  └──────────────────────────────────────┘ │
│                                             │
│  ┌──────────────────────────────────────┐ │
│  │      ConfigMap / Secret              │ │
│  │  (Configuration & Credentials)       │ │
│  └──────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
```

### Components

| Component | Purpose | Replicas |
|-----------|---------|----------|
| Deployment | Manages LeWAF pods | 3-10 (auto-scaled) |
| Service | Load balances traffic | 1 |
| Ingress | External access & TLS | 1 |
| HPA | Auto-scaling | 1 |
| ConfigMap | Configuration files | 1 |
| Secret | Sensitive data | 1 |
| PodDisruptionBudget | HA during updates | 1 |

---

## Configuration

### ConfigMap Structure

The ConfigMap contains two configuration files:

**examples/kubernetes/base/configmap.yaml**:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: lewaf-config
  namespace: lewaf
data:
  lewaf.conf: |
    SecRuleEngine On
    SecRequestBodyAccess On
    # ... more configuration

  crs-setup.conf: |
    # OWASP CRS Configuration
    SecAction "id:900000,phase:1,nolog,pass,setvar:tx.paranoia_level=1"
    # ... more configuration
```

### Update Configuration

```bash
# Edit ConfigMap
kubectl edit configmap lewaf-config -n lewaf

# Or apply updated file
kubectl apply -f configmap.yaml

# Restart pods to pick up changes
kubectl rollout restart deployment/lewaf -n lewaf
```

### Secrets Management

**Create secret manually**:

```bash
# From literal
kubectl create secret generic lewaf-secrets -n lewaf \
  --from-literal=redis-url='redis://redis:6379/0'

# From file
kubectl create secret generic lewaf-secrets -n lewaf \
  --from-file=redis-url=./redis-url.txt
```

**Using external secrets (recommended)**:

```yaml
# Using External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: lewaf-secrets
  namespace: lewaf
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: lewaf-secrets
  data:
    - secretKey: redis-url
      remoteRef:
        key: prod/lewaf/redis-url
```

---

## Deployment Options

### Option 1: kubectl Apply

**Pros**: Simple, direct control
**Cons**: Manual ordering, no templating

```bash
kubectl apply -f examples/kubernetes/base/
```

### Option 2: Kustomize

**Pros**: Overlays for environments, built into kubectl
**Cons**: Limited templating

```bash
# Base deployment
kubectl apply -k examples/kubernetes/base

# Production with overlays
kubectl apply -k examples/kubernetes/overlays/production
```

### Option 3: Helm Chart (Future)

**Pros**: Full templating, versioning, rollbacks
**Cons**: More complex

```bash
# Install chart
helm install lewaf ./charts/lewaf -n lewaf --create-namespace

# Upgrade
helm upgrade lewaf ./charts/lewaf -n lewaf

# Rollback
helm rollback lewaf 1 -n lewaf
```

---

## High Availability

### Pod Distribution

**Anti-affinity rule** (already in deployment.yaml):

```yaml
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app
                operator: In
                values:
                  - lewaf
          topologyKey: kubernetes.io/hostname
```

This ensures pods are distributed across different nodes.

### PodDisruptionBudget

**Ensures minimum availability** during voluntary disruptions:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: lewaf
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: lewaf
```

With 3 replicas and minAvailable: 2, Kubernetes ensures at least 2 pods are running during:
- Node drains
- Cluster upgrades
- Pod evictions

### Multi-Zone Deployment

**Deploy across availability zones**:

```yaml
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app
                operator: In
                values:
                  - lewaf
          topologyKey: topology.kubernetes.io/zone
```

### Health Checks

Three types of probes ensure pod health:

**1. Liveness Probe** - Restart unhealthy pods:
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 30
  periodSeconds: 10
  failureThreshold: 3
```

**2. Readiness Probe** - Remove unhealthy pods from service:
```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 5
  failureThreshold: 3
```

**3. Startup Probe** - Handle slow starts:
```yaml
startupProbe:
  httpGet:
    path: /health
    port: 8000
  periodSeconds: 5
  failureThreshold: 12  # 60 seconds total
```

---

## Auto-Scaling

### Horizontal Pod Autoscaler (HPA)

**Scale based on CPU and memory**:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: lewaf
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: lewaf
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

### View HPA Status

```bash
# Check HPA status
kubectl get hpa -n lewaf

# Watch HPA in real-time
kubectl get hpa -n lewaf -w

# Describe HPA for details
kubectl describe hpa lewaf -n lewaf
```

### Custom Metrics (Advanced)

**Scale based on request rate**:

```yaml
metrics:
  - type: Pods
    pods:
      metric:
        name: lewaf_requests_per_second
      target:
        type: AverageValue
        averageValue: "1000"
```

Requires **Prometheus Adapter** or **KEDA**.

### Scaling Behavior

**Control scale-up/down speed**:

```yaml
behavior:
  scaleDown:
    stabilizationWindowSeconds: 300  # Wait 5 min before scaling down
    policies:
      - type: Percent
        value: 50  # Scale down by 50% at most
        periodSeconds: 60
  scaleUp:
    stabilizationWindowSeconds: 60  # Wait 1 min before scaling up
    policies:
      - type: Pods
        value: 2  # Add 2 pods at a time
        periodSeconds: 30
```

---

## Security

### 1. Run as Non-Root

Already configured in deployment:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 999
  runAsGroup: 999
```

### 2. Read-Only Root Filesystem

```yaml
securityContext:
  readOnlyRootFilesystem: true
```

With tmpfs for writable directories:

```yaml
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

### 3. Drop Capabilities

```yaml
securityContext:
  capabilities:
    drop:
      - ALL
```

### 4. Pod Security Standards

**Apply pod security policy**:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: lewaf
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### 5. Network Policies

**Restrict traffic**:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: lewaf
  namespace: lewaf
spec:
  podSelector:
    matchLabels:
      app: lewaf
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8000
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: redis
      ports:
        - protocol: TCP
          port: 6379
    - to:  # DNS
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
```

### 6. RBAC

**Minimal service account permissions**:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: lewaf
  namespace: lewaf
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: lewaf
  namespace: lewaf
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: lewaf
  namespace: lewaf
subjects:
  - kind: ServiceAccount
    name: lewaf
roleRef:
  kind: Role
  name: lewaf
  apiGroup: rbac.authorization.k8s.io
```

### 7. Secrets Encryption

**Enable secrets encryption at rest**:

```yaml
# encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-secret>
      - identity: {}
```

---

## Monitoring

### Prometheus Integration

**Service annotations** (already in deployment):

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8000"
  prometheus.io/path: "/metrics"
```

### ServiceMonitor (Prometheus Operator)

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: lewaf
  namespace: lewaf
spec:
  selector:
    matchLabels:
      app: lewaf
  endpoints:
    - port: metrics
      path: /metrics
      interval: 30s
```

### Key Metrics to Monitor

- `lewaf_requests_total` - Total requests
- `lewaf_blocked_requests_total` - Blocked requests
- `lewaf_request_duration_seconds` - Latency
- `lewaf_rule_evaluation_duration_seconds` - Rule performance
- `lewaf_memory_usage_bytes` - Memory usage

### Grafana Dashboards

Import dashboards from `grafana-dashboards/`:

```bash
kubectl create configmap grafana-dashboards \
  -n monitoring \
  --from-file=grafana-dashboards/
```

---

## Troubleshooting

### Pod Not Starting

**Check pod status**:

```bash
kubectl get pods -n lewaf
kubectl describe pod lewaf-xxx -n lewaf
```

**Common issues**:

1. **ImagePullBackOff**
   ```bash
   kubectl describe pod lewaf-xxx -n lewaf | grep -A 5 "Events:"
   ```
   **Fix**: Check image name, registry credentials

2. **CrashLoopBackOff**
   ```bash
   kubectl logs lewaf-xxx -n lewaf --previous
   ```
   **Fix**: Check application logs for errors

3. **Pending (insufficient resources)**
   ```bash
   kubectl describe pod lewaf-xxx -n lewaf | grep -A 5 "Events:"
   ```
   **Fix**: Reduce resource requests or add nodes

### Health Check Failures

```bash
# Check probe configuration
kubectl get pod lewaf-xxx -n lewaf -o yaml | grep -A 10 "livenessProbe"

# Test health endpoint manually
kubectl exec -it lewaf-xxx -n lewaf -- curl http://localhost:8000/health
```

### HPA Not Scaling

```bash
# Check metrics server
kubectl get deployment metrics-server -n kube-system

# Check HPA status
kubectl describe hpa lewaf -n lewaf

# View current metrics
kubectl get hpa lewaf -n lewaf -o yaml | grep -A 5 "current"
```

### ConfigMap Changes Not Applied

```bash
# Restart deployment to pick up changes
kubectl rollout restart deployment/lewaf -n lewaf

# Watch rollout status
kubectl rollout status deployment/lewaf -n lewaf
```

### Network Issues

```bash
# Test service connectivity
kubectl run -it --rm debug --image=busybox --restart=Never -n lewaf -- \
  wget -O- http://lewaf/health

# Check service endpoints
kubectl get endpoints lewaf -n lewaf

# Check ingress
kubectl describe ingress lewaf -n lewaf
```

### View Logs

```bash
# All pods
kubectl logs -n lewaf -l app=lewaf --tail=100 -f

# Specific pod
kubectl logs -n lewaf lewaf-xxx --tail=100 -f

# Previous crashed container
kubectl logs -n lewaf lewaf-xxx --previous
```

---

## Best Practices

### 1. Resource Limits

**Always set requests and limits**:

```yaml
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 2Gi
```

**Right-size resources**:
```bash
# Monitor actual usage
kubectl top pods -n lewaf

# Use VPA for recommendations
kubectl get vpa lewaf -n lewaf -o yaml
```

### 2. Rolling Updates

**Configure for zero downtime**:

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 1       # Add 1 new pod before removing old
    maxUnavailable: 0  # Never have fewer than desired replicas
```

### 3. Use Liveness and Readiness Probes

- **Liveness**: Restart unhealthy pods
- **Readiness**: Don't send traffic to unready pods
- **Startup**: Handle slow application starts

### 4. Implement PodDisruptionBudget

Ensure availability during voluntary disruptions.

### 5. Use Anti-Affinity

Distribute pods across nodes/zones for fault tolerance.

### 6. Version Your Images

```yaml
# Bad
image: lewaf:latest

# Good
image: lewaf:v1.0.0
```

### 7. Use Kustomize or Helm

Don't edit manifests directly. Use overlays or values files.

### 8. Enable Monitoring

Integrate with Prometheus and set up alerts.

### 9. Implement Network Policies

Restrict traffic to only what's necessary.

### 10. Regular Security Scans

```bash
# Scan images
trivy image your-registry/lewaf:v1.0.0

# Scan cluster
kube-bench run --targets master,node
```

---

## Next Steps

- **Performance Tuning**: See [../performance/tuning.md](../performance/tuning.md)
- **Security Hardening**: See [../security/hardening.md](../security/hardening.md)
- **Monitoring Setup**: See [../monitoring/prometheus.md](../monitoring/prometheus.md)
- **Troubleshooting**: See [../troubleshooting/runbook.md](../troubleshooting/runbook.md)

---

**Questions or Issues?**
- GitHub Issues: https://github.com/yourorg/lewaf/issues
- Documentation: https://lewaf.readthedocs.io
