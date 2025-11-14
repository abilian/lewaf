# LeWAF Django Integration Guide

Complete guide for integrating LeWAF with Django applications.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Basic Integration](#basic-integration)
3. [Configuration](#configuration)
4. [Advanced Patterns](#advanced-patterns)
5. [Testing](#testing)
6. [Production Deployment](#production-deployment)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Installation

```bash
pip install lewaf django
```

### Minimal Example

**File**: `myapp.py`

```python
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.urls import path
from django.core.wsgi import get_wsgi_application

# Configure Django
if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY='your-secret-key',
        ROOT_URLCONF=__name__,
        MIDDLEWARE=[
            'django.middleware.common.CommonMiddleware',
            '__main__.LeWAFMiddleware',
        ],
        LEWAF_CONFIG={
            "rules": [
                'SecRule ARGS "@rx <script" "id:1,phase:2,deny,msg:\'XSS blocked\'"',
            ],
            "rule_files": []
        }
    )

# LeWAF Middleware
class LeWAFMiddleware:
    """Django middleware for LeWAF integration."""

    def __init__(self, get_response):
        self.get_response = get_response
        from lewaf.integration import WAF
        self.waf = WAF(settings.LEWAF_CONFIG)

    def __call__(self, request):
        # Create transaction
        tx = self.waf.new_transaction()

        # Process request
        tx.process_uri(request.get_full_path(), request.method)

        # Add headers
        for key, value in request.META.items():
            if key.startswith('HTTP_'):
                header_name = key[5:].replace('_', '-').lower()
                tx.variables.request_headers.add(header_name, value)

        # Evaluate Phase 1
        tx.process_request_headers()

        if tx.interruption:
            return self._blocked_response(tx)

        # Process body if present
        if request.body:
            content_type = request.META.get('CONTENT_TYPE', '')
            tx.add_request_body(request.body, content_type)
            tx.process_request_body()

            if tx.interruption:
                return self._blocked_response(tx)

        # Get response
        response = self.get_response(request)
        return response

    def _blocked_response(self, tx):
        """Return blocked response."""
        return JsonResponse({
            'error': 'Request blocked by WAF',
            'rule_id': tx.interruption.get('rule_id') if tx.interruption else None,
            'message': tx.interruption.get('action', 'Unknown') if tx.interruption else 'Unknown'
        }, status=403)

# Views
def home(request):
    return HttpResponse('Hello, Django with LeWAF!')

# URLs
urlpatterns = [
    path('', home),
]

# WSGI app
application = get_wsgi_application()
```

**Run**:
```bash
python myapp.py runserver
```

**Test**:
```bash
# Safe request
curl http://localhost:8000/
# ✅ Hello, Django with LeWAF!

# XSS attempt
curl "http://localhost:8000/?q=<script>alert(1)</script>"
# ⛔ 403 Forbidden
```

---

## Basic Integration

### Method 1: Middleware in Django Project (Recommended)

**Step 1: Create middleware** (`myproject/middleware.py`):

```python
from django.conf import settings
from django.http import JsonResponse
from lewaf.integration import WAF


class LeWAFMiddleware:
    """
    LeWAF middleware for Django.

    Processes all requests through WAF before reaching views.
    """

    def __init__(self, get_response):
        self.get_response = get_response

        # Load WAF configuration from settings
        config = getattr(settings, 'LEWAF_CONFIG', {
            "rules": [],
            "rule_files": []
        })
        self.waf = WAF(config)

    def __call__(self, request):
        """Process request through WAF."""
        # Create new transaction
        tx = self.waf.new_transaction()

        # Set request URI and method
        tx.process_uri(request.get_full_path(), request.method)

        # Add request headers
        for key, value in request.META.items():
            if key.startswith('HTTP_'):
                # Convert HTTP_USER_AGENT -> user-agent
                header_name = key[5:].replace('_', '-').lower()
                tx.variables.request_headers.add(header_name, value)

        # Process Phase 1 (request headers)
        tx.process_request_headers()

        # Check for interruption
        if tx.interruption:
            return self._blocked_response(tx)

        # Process request body for POST/PUT/PATCH
        if request.method in ['POST', 'PUT', 'PATCH'] and request.body:
            content_type = request.META.get('CONTENT_TYPE', '')
            tx.add_request_body(request.body, content_type)
            tx.process_request_body()

            if tx.interruption:
                return self._blocked_response(tx)

        # Store transaction in request for access in views
        request.waf_transaction = tx

        # Get response from Django
        response = self.get_response(request)

        # Process response (optional)
        tx.add_response_status(response.status_code)

        for key, value in response.items():
            tx.add_response_headers({key.lower(): value})

        tx.process_response_headers()

        if hasattr(response, 'content'):
            tx.add_response_body(response.content)
            tx.process_response_body()

        if tx.interruption:
            return self._blocked_response(tx)

        return response

    def _blocked_response(self, tx):
        """Generate blocked response."""
        return JsonResponse({
            'error': 'Request blocked by WAF',
            'rule_id': tx.interruption.get('rule_id') if tx.interruption else None,
            'message': tx.interruption.get('action', 'Unknown') if tx.interruption else 'Unknown',
            'timestamp': tx.id
        }, status=403)
```

**Step 2: Add to settings** (`myproject/settings.py`):

```python
# settings.py

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',

    # Add LeWAF middleware here (after CSRF, before auth)
    'myproject.middleware.LeWAFMiddleware',

    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# LeWAF Configuration
LEWAF_CONFIG = {
    "rules": [
        # XSS Protection
        'SecRule ARGS "@rx <script" "id:100,phase:2,deny,msg:\'XSS Attack\'"',

        # SQL Injection Protection
        'SecRule ARGS "@rx (?i:union.*select)" "id:101,phase:2,deny,msg:\'SQL Injection\'"',

        # Admin protection
        'SecRule REQUEST_URI "@rx ^/admin" "id:102,phase:1,chain"',
        'SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8" "deny,msg:\'Admin access restricted\'"',
    ],
    "rule_files": []
}
```

**Step 3: Create views**:

```python
# views.py
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods


@require_http_methods(["GET"])
def users_list(request):
    """List users endpoint."""
    return JsonResponse({
        'users': [
            {'id': 1, 'name': 'Alice'},
            {'id': 2, 'name': 'Bob'},
        ]
    })


@require_http_methods(["POST"])
def users_create(request):
    """Create user endpoint."""
    import json
    data = json.loads(request.body)

    return JsonResponse({
        'id': 3,
        'name': data.get('name'),
        'email': data.get('email')
    }, status=201)
```

### Method 2: Configuration File

**File**: `config/lewaf.yaml`

```yaml
# LeWAF configuration for Django
rules:
  # Django-specific protections
  - 'SecRule REQUEST_URI "@rx /admin/.*" "id:200,phase:1,chain"'
  - 'SecRule REQUEST_COOKIES:sessionid "^$" "deny,status:401,msg:''Admin requires session''"'

  # CSRF Protection (additional to Django's)
  - 'SecRule REQUEST_METHOD "@rx ^(POST|PUT|DELETE)$" "id:201,phase:1,chain"'
  - 'SecRule REQUEST_HEADERS:X-CSRFToken "^$" "log,msg:''Missing CSRF token''"'

  # Form validation
  - 'SecRule ARGS "@rx <script" "id:202,phase:2,deny,msg:''XSS in form data''"'

rule_files:
  - "rules/django-custom.conf"
  - "rules/crs-setup.conf"
  - "rules/REQUEST-*.conf"

log:
  level: INFO
  format: json
```

**Load in settings**:

```python
# settings.py
import yaml
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Load LeWAF config from file
with open(BASE_DIR / 'config' / 'lewaf.yaml') as f:
    LEWAF_CONFIG = yaml.safe_load(f)
```

### Method 3: App-Based Integration

**File**: `myapp/apps.py`

```python
from django.apps import AppConfig


class MyAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'myapp'

    def ready(self):
        """Initialize LeWAF when app is ready."""
        from django.conf import settings
        from lewaf.integration import WAF

        # Initialize WAF globally
        if not hasattr(settings, '_waf_instance'):
            config = getattr(settings, 'LEWAF_CONFIG', {"rules": [], "rule_files": []})
            settings._waf_instance = WAF(config)
```

---

## Configuration

### Full Configuration Example

**File**: `settings.py`

```python
# Django LeWAF Configuration

LEWAF_CONFIG = {
    "rules": [
        # === Request Validation ===

        # Block invalid HTTP methods
        'SecRule REQUEST_METHOD "!@rx ^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$" '
        '"id:1001,phase:1,deny,status:405,msg:\'Invalid HTTP method\'"',

        # Require Content-Type for POST/PUT
        'SecRule REQUEST_METHOD "@rx ^(POST|PUT|PATCH)$" '
        '"id:1002,phase:1,chain"',
        'SecRule REQUEST_HEADERS:Content-Type "^$" '
        '"deny,status:400,msg:\'Content-Type required\'"',

        # === Django-Specific Rules ===

        # Protect Django admin
        'SecRule REQUEST_URI "@beginsWith /admin/" '
        '"id:2001,phase:1,chain"',
        'SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8,192.168.0.0/16" '
        '"deny,status:403,msg:\'Admin access from unauthorized IP\'"',

        # Protect Django debug toolbar
        'SecRule REQUEST_URI "@beginsWith /__debug__/" '
        '"id:2002,phase:1,deny,status:404,msg:\'Debug toolbar disabled\'"',

        # Validate Django session cookie
        'SecRule REQUEST_COOKIES:sessionid "!@rx ^[a-z0-9]{32}$" '
        '"id:2003,phase:1,log,msg:\'Invalid session cookie format\'"',

        # === Security Rules ===

        # XSS Protection
        'SecRule ARGS|REQUEST_BODY "@rx <script[^>]*>" '
        '"id:3001,phase:2,deny,t:urlDecode,t:htmlEntityDecode,msg:\'XSS Attack\'"',

        # SQL Injection
        'SecRule ARGS|REQUEST_BODY "@rx (?i:union.*select|insert.*into|delete.*from)" '
        '"id:3002,phase:2,deny,t:urlDecode,msg:\'SQL Injection\'"',

        # Path Traversal
        'SecRule REQUEST_URI "@rx \\.\\./|\\.\\.\\\\" '
        '"id:3003,phase:1,deny,msg:\'Path Traversal\'"',

        # Command Injection
        'SecRule ARGS "@rx [;&|`$()]" '
        '"id:3004,phase:2,deny,msg:\'Command Injection\'"',
    ],

    "rule_files": [
        # Load OWASP CRS rules
        # "rules/crs-setup.conf",
        # "rules/REQUEST-*.conf",
    ]
}

# Environment-specific overrides
if DEBUG:
    # Lenient rules for development
    LEWAF_CONFIG['rules'] = [
        'SecRule ARGS "@rx <script" "id:1,phase:2,log,msg:\'XSS (dev mode)\'"',
    ]
else:
    # Strict rules for production
    LEWAF_CONFIG['rules'].extend([
        # Rate limiting in production
        'SecRule REMOTE_ADDR "@unconditionalMatch" '
        '"id:4001,phase:1,pass,setvar:ip.req_count=+1"',

        'SecRule IP:REQ_COUNT "@gt 100" '
        '"id:4002,phase:1,deny,status:429,msg:\'Rate limit exceeded\'"',
    ])
```

### Custom Rule File

**File**: `rules/django-custom.conf`

```apache
# Django-Specific WAF Rules

SecRuleEngine On

SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# === Django Admin Protection ===

# Only allow admin access during business hours
SecRule REQUEST_URI "@beginsWith /admin/" \
    "id:10001,phase:1,chain"
    SecRule TIME_HOUR "@lt 8" \
        "chain"
        SecRule TIME_HOUR "@gt 18" \
            "deny,msg:'Admin access only during business hours (8AM-6PM)'"

# Require strong session for admin
SecRule REQUEST_URI "@beginsWith /admin/" \
    "id:10002,phase:1,chain"
    SecRule REQUEST_COOKIES:sessionid "^$" \
        "deny,status:401,msg:'Admin requires authentication'"

# === Django REST Framework ===

# Validate JWT tokens in Authorization header
SecRule REQUEST_URI "@beginsWith /api/" \
    "id:10100,phase:1,chain"
    SecRule REQUEST_HEADERS:Authorization "^$" \
        "deny,status:401,msg:'API requires authentication'"

# Require JSON for API POST/PUT
SecRule REQUEST_URI "@beginsWith /api/" \
    "id:10101,phase:1,chain"
    SecRule REQUEST_METHOD "@rx ^(POST|PUT|PATCH)$" \
        "chain"
        SecRule REQUEST_HEADERS:Content-Type "!@contains application/json" \
            "deny,status:415,msg:'API requires application/json'"

# === Form Protection ===

# Validate email format in form submissions
SecRule ARGS:email "!@rx ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" \
    "id:10200,phase:2,deny,status:400,msg:'Invalid email format'"

# Limit textarea length
SecRule ARGS:message "@gt 5000" \
    "id:10201,phase:2,deny,status:400,msg:'Message too long (max 5000 chars)'"

# Block file uploads with dangerous extensions
SecRule FILES_NAMES "@rx \\.(php|exe|sh|bat|cmd)$" \
    "id:10202,phase:2,deny,msg:'Dangerous file extension'"

# === Rate Limiting ===

# Track requests per IP
SecAction "id:10300,phase:1,nolog,initcol:IP=%{REMOTE_ADDR}"
SecAction "id:10301,phase:1,nolog,setvar:IP.requests=+1"

# Block if too many requests
SecRule IP:requests "@gt 100" \
    "id:10302,phase:1,deny,status:429,msg:'Rate limit: 100 requests/hour'"

# Reset counter every hour
SecRule REMOTE_ADDR "@unconditionalMatch" \
    "id:10303,phase:5,pass,expirevar:IP.requests=3600"
```

---

## Advanced Patterns

### Pattern 1: Class-Based Views with WAF

```python
# views.py
from django.views import View
from django.http import JsonResponse
import json


class ProtectedAPIView(View):
    """Base view with WAF transaction access."""

    def dispatch(self, request, *args, **kwargs):
        # Access WAF transaction
        tx = getattr(request, 'waf_transaction', None)

        if tx:
            # Log transaction ID
            print(f"WAF Transaction: {tx.id}")

        return super().dispatch(request, *args, **kwargs)


class UserListView(ProtectedAPIView):
    """List users with WAF protection."""

    def get(self, request):
        return JsonResponse({
            'users': [
                {'id': 1, 'name': 'Alice'},
                {'id': 2, 'name': 'Bob'},
            ]
        })

    def post(self, request):
        data = json.loads(request.body)

        # WAF already validated input
        return JsonResponse({
            'id': 3,
            'name': data.get('name'),
            'email': data.get('email')
        }, status=201)
```

### Pattern 2: Django REST Framework Integration

```python
# middleware.py
from rest_framework.response import Response
from rest_framework import status


class DRFLeWAFMiddleware(LeWAFMiddleware):
    """LeWAF middleware optimized for Django REST Framework."""

    def _blocked_response(self, tx):
        """Return DRF-compatible blocked response."""
        from rest_framework.response import Response

        return Response(
            {
                'error': 'request_blocked',
                'detail': 'Request blocked by Web Application Firewall',
                'rule_id': tx.interruption.get('rule_id') if tx.interruption else None,
                'code': tx.interruption.get('action', 'deny') if tx.interruption else 'deny'
            },
            status=status.HTTP_403_FORBIDDEN
        )


# views.py (DRF)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


class UserViewSet(APIView):
    """User API with WAF protection."""

    def get(self, request):
        """List users."""
        return Response({
            'users': [
                {'id': 1, 'name': 'Alice'},
                {'id': 2, 'name': 'Bob'},
            ]
        })

    def post(self, request):
        """Create user."""
        # Input already validated by WAF
        return Response({
            'id': 3,
            'name': request.data.get('name'),
            'email': request.data.get('email')
        }, status=status.HTTP_201_CREATED)
```

### Pattern 3: Per-App Middleware

**Enable WAF only for specific apps**:

```python
# middleware.py
from django.conf import settings


class SelectiveLeWAFMiddleware(LeWAFMiddleware):
    """Apply WAF only to specific URL patterns."""

    def __call__(self, request):
        # Define protected paths
        protected_paths = ['/admin/', '/api/', '/accounts/']

        # Check if request needs WAF protection
        needs_protection = any(
            request.path.startswith(path)
            for path in protected_paths
        )

        if not needs_protection:
            # Skip WAF for this request
            return self.get_response(request)

        # Apply WAF protection
        return super().__call__(request)
```

### Pattern 4: Custom Error Pages

```python
# middleware.py
from django.shortcuts import render


class LeWAFMiddlewareWithCustomErrors(LeWAFMiddleware):
    """LeWAF middleware with custom error pages."""

    def _blocked_response(self, tx):
        """Render custom blocked page."""
        context = {
            'rule_id': tx.interruption.get('rule_id') if tx.interruption else None,
            'message': tx.interruption.get('action') if tx.interruption else 'Unknown',
            'timestamp': tx.id,
        }

        # Render template
        return render(
            None,  # Request not needed for render
            'waf/blocked.html',
            context,
            status=403
        )
```

**Template** (`templates/waf/blocked.html`):

```html
<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 100px auto;
            text-align: center;
        }
        .error-box {
            background: #fee;
            border: 2px solid #c33;
            border-radius: 8px;
            padding: 30px;
        }
        h1 { color: #c33; }
        .details {
            font-family: monospace;
            font-size: 12px;
            color: #666;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="error-box">
        <h1>⛔ Access Denied</h1>
        <p>Your request was blocked by our security system.</p>
        <p>If you believe this is an error, please contact support.</p>

        <div class="details">
            <p>Rule ID: {{ rule_id }}</p>
            <p>Incident: {{ timestamp }}</p>
        </div>
    </div>
</body>
</html>
```

### Pattern 5: Management Command for Testing Rules

```python
# management/commands/test_waf.py
from django.core.management.base import BaseCommand
from django.conf import settings
from lewaf.integration import WAF


class Command(BaseCommand):
    help = 'Test WAF rules'

    def add_arguments(self, parser):
        parser.add_argument('--uri', type=str, default='/', help='URI to test')
        parser.add_argument('--method', type=str, default='GET', help='HTTP method')
        parser.add_argument('--param', action='append', help='Query parameter (name=value)')

    def handle(self, *args, **options):
        # Load WAF
        config = settings.LEWAF_CONFIG
        waf = WAF(config)

        # Create transaction
        tx = waf.new_transaction()

        # Build URI with parameters
        uri = options['uri']
        if options['param']:
            params = '&'.join(options['param'])
            uri = f"{uri}?{params}"

        # Process request
        tx.process_uri(uri, options['method'])
        tx.process_request_headers()

        # Check result
        if tx.interruption:
            self.stdout.write(self.style.ERROR(
                f"⛔ Request BLOCKED by rule {tx.interruption.get('rule_id')}"
            ))
            self.stdout.write(f"   Message: {tx.interruption.get('action')}")
        else:
            self.stdout.write(self.style.SUCCESS(
                "✅ Request ALLOWED"
            ))
```

**Usage**:

```bash
# Test safe request
python manage.py test_waf --uri /api/users --method GET

# Test XSS attack
python manage.py test_waf --uri /search --param "q=<script>alert(1)</script>"

# Test SQL injection
python manage.py test_waf --uri /users --param "id=' OR '1'='1"
```

### Pattern 6: Celery Task for Audit Log Analysis

```python
# tasks.py
from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
import json


@shared_task
def analyze_waf_logs():
    """
    Analyze WAF logs and send alerts.

    Run this task periodically (e.g., every hour) to detect attack patterns.
    """
    # Read recent WAF logs
    log_file = settings.BASE_DIR / 'logs' / 'waf.log'

    blocked_requests = []

    with open(log_file) as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                if log_entry.get('blocked'):
                    blocked_requests.append(log_entry)
            except json.JSONDecodeError:
                continue

    # Analyze patterns
    if len(blocked_requests) > 100:
        # Send alert email
        send_mail(
            subject='WAF Alert: High Block Rate',
            message=f'Detected {len(blocked_requests)} blocked requests in the last hour.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[settings.SECURITY_EMAIL],
        )


# In settings.py
from celery.schedules import crontab

CELERYBEAT_SCHEDULE = {
    'analyze-waf-logs': {
        'task': 'myapp.tasks.analyze_waf_logs',
        'schedule': crontab(minute=0),  # Every hour
    },
}
```

---

## Testing

### Unit Tests

```python
# tests/test_waf_middleware.py
from django.test import TestCase, RequestFactory
from django.conf import settings
from myproject.middleware import LeWAFMiddleware


class WAFMiddlewareTestCase(TestCase):
    """Test LeWAF middleware."""

    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = LeWAFMiddleware(get_response=lambda r: None)

    def test_safe_request_allowed(self):
        """Test that safe requests pass through."""
        request = self.factory.get('/api/users/')
        response = self.middleware(request)

        # Should not be blocked
        self.assertNotEqual(response.status_code, 403)

    def test_xss_attack_blocked(self):
        """Test that XSS attacks are blocked."""
        request = self.factory.get('/search/?q=<script>alert(1)</script>')
        response = self.middleware(request)

        # Should be blocked
        self.assertEqual(response.status_code, 403)

        # Check error message
        data = response.json()
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Request blocked by WAF')

    def test_sql_injection_blocked(self):
        """Test that SQL injection is blocked."""
        request = self.factory.get("/users/?id=' OR '1'='1")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_post_request_with_body(self):
        """Test POST request body processing."""
        import json

        request = self.factory.post(
            '/api/users/',
            data=json.dumps({'name': '<script>xss</script>'}),
            content_type='application/json'
        )

        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)
```

### Integration Tests

```python
# tests/test_views.py
from django.test import TestCase, Client
import json


class ViewsTestCase(TestCase):
    """Test views with WAF protection."""

    def setUp(self):
        self.client = Client()

    def test_users_list_safe_request(self):
        """Test safe request to users list."""
        response = self.client.get('/api/users/')

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('users', data)

    def test_users_list_xss_attack(self):
        """Test XSS attack on users list."""
        response = self.client.get('/api/users/?name=<script>alert(1)</script>')

        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertIn('error', data)

    def test_users_create_safe(self):
        """Test safe user creation."""
        response = self.client.post(
            '/api/users/',
            data=json.dumps({
                'name': 'Alice',
                'email': 'alice@example.com'
            }),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 201)

    def test_users_create_xss(self):
        """Test XSS in user creation."""
        response = self.client.post(
            '/api/users/',
            data=json.dumps({
                'name': '<script>alert(1)</script>',
                'email': 'test@example.com'
            }),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 403)

    def test_admin_access_restricted(self):
        """Test admin access restriction."""
        response = self.client.get('/admin/')

        # Should be blocked if rule configured
        # (depends on your configuration)
        self.assertIn(response.status_code, [403, 302])  # Blocked or redirect to login
```

### Load Testing

```python
# locustfile.py
from locust import HttpUser, task, between


class DjangoWAFUser(HttpUser):
    """Load test Django app with WAF."""

    wait_time = between(1, 3)

    @task(3)
    def get_users(self):
        """Safe request - should succeed."""
        self.client.get('/api/users/')

    @task(1)
    def create_user(self):
        """Safe POST - should succeed."""
        self.client.post(
            '/api/users/',
            json={'name': 'Test User', 'email': 'test@example.com'}
        )

    @task(1)
    def xss_attempt(self):
        """Attack request - should be blocked."""
        self.client.get('/search/?q=<script>alert(1)</script>')


# Run: locust -f locustfile.py --host http://localhost:8000
```

---

## Production Deployment

### Gunicorn with Gevent Workers

**File**: `gunicorn.conf.py`

```python
# Gunicorn configuration for Django with LeWAF

import multiprocessing

# Server socket
bind = '0.0.0.0:8000'
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'gevent'  # Async worker for better performance
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 30
keepalive = 2

# Logging
accesslog = '/var/log/django/access.log'
errorlog = '/var/log/django/error.log'
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'django-lewaf'

# Server mechanics
daemon = False
pidfile = '/var/run/django-lewaf.pid'
user = 'www-data'
group = 'www-data'
tmp_upload_dir = None

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190
```

**Run**:

```bash
gunicorn myproject.wsgi:application -c gunicorn.conf.py
```

### Docker Deployment

**Dockerfile**:

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput

# Create non-root user
RUN useradd -m -u 1000 django && \
    chown -R django:django /app

USER django

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/')"

# Run Gunicorn
CMD ["gunicorn", "myproject.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--worker-class", "gevent"]
```

**docker-compose.yml**:

```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/mydb
      - DJANGO_SETTINGS_MODULE=myproject.settings.production
      - SECRET_KEY=${SECRET_KEY}
    depends_on:
      - db
      - redis
    volumes:
      - ./config:/app/config
      - ./rules:/app/rules
      - ./logs:/app/logs
    restart: unless-stopped

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=mydb
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

### Kubernetes Deployment

**deployment.yaml**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: django-waf
spec:
  replicas: 3
  selector:
    matchLabels:
      app: django-waf
  template:
    metadata:
      labels:
        app: django-waf
    spec:
      containers:
      - name: django
        image: myregistry/django-waf:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: django-secrets
              key: database-url
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: django-secrets
              key: secret-key
        - name: DJANGO_SETTINGS_MODULE
          value: "myproject.settings.production"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health/
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: rules
          mountPath: /app/rules
      volumes:
      - name: config
        configMap:
          name: lewaf-config
      - name: rules
        configMap:
          name: lewaf-rules
---
apiVersion: v1
kind: Service
metadata:
  name: django-waf-service
spec:
  selector:
    app: django-waf
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

### Systemd Service

**File**: `/etc/systemd/system/django-waf.service`

```ini
[Unit]
Description=Django Application with LeWAF
After=network.target postgresql.service

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/opt/django-app
Environment="PATH=/opt/django-app/venv/bin"
Environment="DJANGO_SETTINGS_MODULE=myproject.settings.production"
ExecStart=/opt/django-app/venv/bin/gunicorn myproject.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 4 \
    --worker-class gevent \
    --access-logfile /var/log/django-waf/access.log \
    --error-logfile /var/log/django-waf/error.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start**:

```bash
sudo systemctl enable django-waf
sudo systemctl start django-waf
sudo systemctl status django-waf
```

---

## Troubleshooting

### Issue 1: "WAF not blocking attacks"

**Symptom**: Malicious requests pass through WAF.

**Causes**:
1. Middleware not in MIDDLEWARE list
2. Middleware in wrong order
3. Rules not loaded correctly

**Solutions**:

```python
# Check middleware is enabled
print(settings.MIDDLEWARE)
# Should include: 'myproject.middleware.LeWAFMiddleware'

# Check middleware order (should be after CSRF, before Auth)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'myproject.middleware.LeWAFMiddleware',  # ← Here
    'django.contrib.auth.middleware.AuthenticationMiddleware',
]

# Test WAF directly
from django.conf import settings
from lewaf.integration import WAF

waf = WAF(settings.LEWAF_CONFIG)
tx = waf.new_transaction()
tx.process_uri("/?q=<script>", "GET")
result = tx.process_request_headers()
print(f"Blocked: {result is not None}")  # Should be True
```

### Issue 2: "All requests blocked (false positives)"

**Symptom**: Legitimate requests return 403.

**Solutions**:

1. **Check rules are not too broad**:

```python
# BAD: Blocks word "admin" everywhere
'SecRule REQUEST_BODY "@contains admin" "id:1,phase:2,deny"'

# GOOD: Only blocks admin in specific parameter
'SecRule ARGS:username "@streq admin" "id:1,phase:2,deny"'
```

2. **Add exceptions for safe patterns**:

```python
# Allow specific user agents
'SecRule REQUEST_HEADERS:User-Agent "@contains MyApp" "id:999,phase:1,allow"'

# Skip WAF for static files
class LeWAFMiddleware:
    def __call__(self, request):
        # Skip WAF for static files
        if request.path.startswith('/static/'):
            return self.get_response(request)

        # Continue with WAF...
```

### Issue 3: "Performance degradation"

**Symptom**: Slow response times with WAF enabled.

**Solutions**:

1. **Use early phase checks**:

```python
# BAD: Phase 2 (reads full body)
'SecRule ARGS:token "@eq badtoken" "id:1,phase:2,deny"'

# GOOD: Phase 1 (header only)
'SecRule REQUEST_HEADERS:X-API-Token "@eq badtoken" "id:1,phase:1,deny"'
```

2. **Optimize regex**:

```python
# BAD: Catastrophic backtracking
'SecRule ARGS "@rx (a+)+(b+)+" "id:1,phase:2,deny"'

# GOOD: Bounded pattern
'SecRule ARGS "@rx ^[ab]{1,100}$" "id:1,phase:2,deny"'
```

3. **Skip response body inspection**:

```python
class LeWAFMiddleware:
    def __call__(self, request):
        # ... request processing ...

        response = self.get_response(request)

        # Skip response body inspection (performance)
        # tx.add_response_status(response.status_code)
        # tx.process_response_headers()

        return response
```

### Issue 4: "Middleware not receiving POST data"

**Symptom**: WAF can't inspect request body.

**Cause**: Django's request.body can only be read once.

**Solution**:

```python
class LeWAFMiddleware:
    def __call__(self, request):
        # ... header processing ...

        # Read body (this caches it in request._body)
        if request.method in ['POST', 'PUT', 'PATCH']:
            body = request.body  # Read once, cached

            if body:
                content_type = request.META.get('CONTENT_TYPE', '')
                tx.add_request_body(body, content_type)
                tx.process_request_body()

        # Django views can still access request.body (from cache)
        response = self.get_response(request)
        return response
```

### Issue 5: "CSRF token validation failing"

**Symptom**: Valid CSRF tokens rejected.

**Cause**: WAF middleware running before CSRF middleware.

**Solution**: Ensure correct middleware order:

```python
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',  # ← First
    'myproject.middleware.LeWAFMiddleware',       # ← After CSRF
]
```

### Issue 6: "Admin access blocked"

**Symptom**: Can't access Django admin.

**Solutions**:

1. **Add IP whitelist**:

```python
# In rules
'SecRule REQUEST_URI "@beginsWith /admin/" \
    "id:1,phase:1,chain"'
'SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8,192.168.0.0/16" \
    "allow"'
```

2. **Disable WAF for admin**:

```python
class SelectiveLeWAFMiddleware(LeWAFMiddleware):
    def __call__(self, request):
        if request.path.startswith('/admin/'):
            return self.get_response(request)

        return super().__call__(request)
```

---

## Best Practices

### 1. Configuration

- ✅ Use environment-specific settings (dev/staging/prod)
- ✅ Store sensitive data in environment variables
- ✅ Version control rule files
- ✅ Test in development before deploying to production

### 2. Performance

- ✅ Place middleware after CSRF, before authentication
- ✅ Skip WAF for static files
- ✅ Use phase 1 rules when possible
- ✅ Avoid response body inspection unless necessary

### 3. Security

- ✅ Keep LeWAF and Django updated
- ✅ Use OWASP CRS as baseline
- ✅ Add Django-specific rules
- ✅ Enable audit logging
- ✅ Monitor blocked requests

### 4. Testing

- ✅ Write unit tests for middleware
- ✅ Test both safe and malicious inputs
- ✅ Monitor false positive rate
- ✅ Load test with WAF enabled

---

## Related Documentation

- [Quickstart Guide](quickstart.md)
- [API Reference](../api/reference.md)
- [Flask Integration](integration-flask.md)
- [FastAPI Integration](integration-fastapi.md)
- [Starlette Integration](integration-starlette.md)
- [Custom Rules Guide](custom-rules.md)

---

**Last Updated**: 2025-11-14
**Version**: 1.0.0
