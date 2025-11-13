"""
Django integration example for LeWAF.

This example shows how to integrate LeWAF with Django using middleware.
"""

from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.core.wsgi import get_wsgi_application
from django.http import HttpResponse, JsonResponse
from django.urls import path

# Configure Django settings
if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY="django-insecure-example-key",
        ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["*"],
        MIDDLEWARE=[
            "django.middleware.security.SecurityMiddleware",
            "django.middleware.common.CommonMiddleware",
            # LeWAF middleware (see below)
            "django_example.LeWAFMiddleware",
        ],
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
        ],
        # LeWAF configuration
        LEWAF_CONFIG={
            "engine": "DetectionOnly",
            "rule_files": [
                str(Path(__file__).parent.parent.parent / "coraza.conf"),
            ],
            "request_body_limit": 13107200,
            "custom_rules": [
                'SecRule ARGS:admin "@rx ^true$" "id:9001,phase:1,deny,msg:\'Admin access forbidden\'"',
            ],
        },
    )


# Django Middleware for LeWAF
class LeWAFMiddleware:
    """
    Django middleware that integrates LeWAF.

    This middleware processes all requests through LeWAF before
    passing them to Django views.
    """

    def __init__(self, get_response):
        self.get_response = get_response

        # Import here to avoid issues if lewaf is not installed
        from lewaf.engine import WAF  # noqa: PLC0415 - Avoids circular import

        # Initialize WAF
        config = settings.LEWAF_CONFIG
        self.waf = WAF(**config)

    def __call__(self, request):
        # Create WAF transaction
        tx = self.waf.new_transaction()

        # Process request headers
        headers = {
            key: value for key, value in request.META.items() if key.startswith("HTTP_")
        }

        tx.process_request_headers(
            method=request.method,
            uri=request.get_full_path(),
            protocol=request.META.get("SERVER_PROTOCOL", "HTTP/1.1"),
            headers=headers,
        )

        # Check for interruption after headers
        if tx.interruption:
            return self._blocked_response(tx)

        # Process request body if present
        if request.body:
            tx.process_request_body(request.body)

            # Check for interruption after body
            if tx.interruption:
                return self._blocked_response(tx)

        # Get response from Django
        response = self.get_response(request)

        # Process response headers
        response_headers = dict(response.items())
        tx.process_response_headers(
            status=response.status_code,
            headers=response_headers,
        )

        # Process response body
        if hasattr(response, "content"):
            tx.process_response_body(response.content)

        # Check for interruption after response
        if tx.interruption:
            return self._blocked_response(tx)

        return response

    def _blocked_response(self, tx):
        """Generate a blocked response."""
        return JsonResponse(
            {
                "error": "Request blocked by WAF",
                "rule_id": tx.interruption.rule_id if tx.interruption else None,
                "message": tx.interruption.action if tx.interruption else "Unknown",
            },
            status=403,
        )


# Django Views
def home(request):
    """Home page."""
    return HttpResponse("Hello from Django with LeWAF protection!")


def api_users(request):
    """Example API endpoint."""
    return JsonResponse({
        "users": [
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"},
        ]
    })


def health(request):
    """Health check endpoint."""
    return JsonResponse({
        "status": "healthy",
        "service": "django-lewaf",
    })


# URL Configuration
urlpatterns = [
    path("", home),
    path("api/users/", api_users),
    path("health/", health),
]

# WSGI Application
application = get_wsgi_application()


if __name__ == "__main__":
    import sys

    from django.core.management import execute_from_command_line

    # Run development server
    execute_from_command_line(sys.argv or ["manage.py", "runserver", "0.0.0.0:8000"])
