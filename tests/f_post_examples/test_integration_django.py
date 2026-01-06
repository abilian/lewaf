"""Integration tests for Django framework integration.

These tests use Django's RequestFactory to test the middleware directly,
without requiring Django to be fully configured with URL routing.

IMPORTANT: Django configuration is done in a fixture, not at module import time,
to avoid conflicts with other Django tests in the test suite.
"""

from __future__ import annotations

import pytest

# Skip all tests if Django is not installed
pytest.importorskip("django")


@pytest.fixture(scope="module", autouse=True)
def configure_django():
    """Configure Django for these tests.

    This runs after test collection but before test execution,
    avoiding conflicts with other Django test modules.
    """
    from django.conf import settings

    # Skip configuration if Django is already set up (by example tests)
    if settings.configured:
        yield
        return

    settings.configure(
        DEBUG=True,
        DATABASES={},
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
        ],
        SECRET_KEY="test-secret-key-for-lewaf-testing",
        ROOT_URLCONF="tests.f_post_examples.test_integration_django",
        LEWAF_CONFIG={
            "rules": [],
        },
    )

    import django
    django.setup()
    yield


# Minimal URL patterns for ROOT_URLCONF (imported lazily)
def _dummy_view(request):
    from django.http import HttpResponse
    return HttpResponse("OK")


# URL patterns - use try/except for import to handle collection phase
try:
    from django.urls import path
    urlpatterns = [path("", _dummy_view)]
except Exception:
    urlpatterns = []


@pytest.fixture(autouse=True)
def reset_waf_fixture():
    """Reset WAF instance between tests."""
    from lewaf.integrations.django import reset_waf
    reset_waf()
    yield
    reset_waf()


def test_django_middleware_initialization():
    """Test LeWAFMiddleware initialization."""
    from django.http import HttpResponse

    from lewaf.integrations.django import LeWAFMiddleware

    def get_response(request):
        return HttpResponse("OK")

    middleware = LeWAFMiddleware(get_response)
    assert middleware.waf is not None
    assert middleware.block_status == 403


def test_middleware_with_config():
    """Test middleware loads rules from settings."""
    from django.http import HttpResponse
    from django.test import override_settings

    from lewaf.integrations.django import LeWAFMiddleware, reset_waf

    with override_settings(
        LEWAF_CONFIG={"rules": ['SecRule ARGS "@rx attack" "id:1001,phase:2,deny"']}
    ):
        reset_waf()

        def get_response(request):
            return HttpResponse("OK")

        middleware = LeWAFMiddleware(get_response)
        assert middleware.waf is not None


def test_normal_request_passthrough():
    """Test that normal requests pass through without blocking."""
    from django.http import JsonResponse
    from django.test import RequestFactory

    from lewaf.integrations.django import LeWAFMiddleware, reset_waf

    reset_waf()

    factory = RequestFactory()
    request = factory.get("/")

    def get_response(req):
        return JsonResponse({"message": "Hello World"})

    middleware = LeWAFMiddleware(get_response)
    response = middleware(request)

    assert response.status_code == 200


def test_malicious_request_blocking():
    """Test that malicious requests matching rules are blocked."""
    from django.http import JsonResponse
    from django.test import RequestFactory, override_settings

    from lewaf.integrations.django import LeWAFMiddleware, reset_waf

    with override_settings(
        LEWAF_CONFIG={
            "rules": [
                'SecRule ARGS:attack "@rx malicious" "id:3001,phase:2,deny,log,msg:\'Attack detected\'"'
            ]
        }
    ):
        reset_waf()

        factory = RequestFactory()

        def get_response(req):
            return JsonResponse({"message": "OK"})

        middleware = LeWAFMiddleware(get_response)

        # Normal request should pass
        normal_request = factory.get("/echo?normal=data")
        normal_response = middleware(normal_request)
        assert normal_response.status_code == 200

        # Malicious request should be blocked
        malicious_request = factory.get("/echo?attack=malicious")
        malicious_response = middleware(malicious_request)
        assert malicious_response.status_code == 403


def test_header_based_blocking():
    """Test WAF rules based on request headers."""
    from django.http import JsonResponse
    from django.test import RequestFactory, override_settings

    from lewaf.integrations.django import LeWAFMiddleware, reset_waf

    with override_settings(
        LEWAF_CONFIG={
            "rules": [
                'SecRule REQUEST_HEADERS:User-Agent "@rx (bot|crawler)" "id:3003,phase:1,deny,log"'
            ]
        }
    ):
        reset_waf()

        factory = RequestFactory()

        def get_response(req):
            return JsonResponse({"message": "OK"})

        middleware = LeWAFMiddleware(get_response)

        # Normal user agent should pass
        normal_request = factory.get("/", HTTP_USER_AGENT="Mozilla/5.0")
        normal_response = middleware(normal_request)
        assert normal_response.status_code == 200

        # Bot user agent should be blocked
        bot_request = factory.get("/", HTTP_USER_AGENT="malicious-bot/1.0")
        bot_response = middleware(bot_request)
        assert bot_response.status_code == 403


def test_uri_based_rules():
    """Test WAF rules that examine the request URI."""
    from django.http import JsonResponse
    from django.test import RequestFactory, override_settings

    from lewaf.integrations.django import LeWAFMiddleware, reset_waf

    with override_settings(
        LEWAF_CONFIG={
            "rules": [
                'SecRule REQUEST_URI "@rx admin" "id:3010,phase:1,deny,log"'
            ]
        }
    ):
        reset_waf()

        factory = RequestFactory()

        def get_response(req):
            return JsonResponse({"message": "OK"})

        middleware = LeWAFMiddleware(get_response)

        # Normal path should pass
        normal_request = factory.get("/echo")
        normal_response = middleware(normal_request)
        assert normal_response.status_code == 200

        # Admin path should be blocked
        admin_request = factory.get("/admin/panel")
        admin_response = middleware(admin_request)
        assert admin_response.status_code == 403


def test_query_parameter_validation():
    """Test WAF validation of query parameters."""
    from django.http import JsonResponse
    from django.test import RequestFactory, override_settings

    from lewaf.integrations.django import LeWAFMiddleware, reset_waf

    with override_settings(
        LEWAF_CONFIG={
            "rules": [
                'SecRule ARGS:id "@rx [^0-9]" "id:3006,phase:2,deny,log"'
            ]
        }
    ):
        reset_waf()

        factory = RequestFactory()

        def get_response(req):
            return JsonResponse({"message": "OK"})

        middleware = LeWAFMiddleware(get_response)

        # Valid numeric ID should pass
        valid_request = factory.get("/echo?id=123")
        valid_response = middleware(valid_request)
        assert valid_response.status_code == 200

        # Invalid ID format should be blocked
        invalid_request = factory.get("/echo?id=abc123")
        invalid_response = middleware(invalid_request)
        assert invalid_response.status_code == 403


def test_multiple_rule_evaluation():
    """Test evaluation of multiple rules in sequence."""
    from django.http import JsonResponse
    from django.test import RequestFactory, override_settings

    from lewaf.integrations.django import LeWAFMiddleware, reset_waf

    with override_settings(
        LEWAF_CONFIG={
            "rules": [
                'SecRule ARGS:test1 "@rx danger" "id:3007,phase:2,deny,log"',
                'SecRule ARGS:test2 "@rx evil" "id:3008,phase:2,deny,log"',
            ]
        }
    ):
        reset_waf()

        factory = RequestFactory()

        def get_response(req):
            return JsonResponse({"message": "OK"})

        middleware = LeWAFMiddleware(get_response)

        # First rule should block
        request1 = factory.get("/echo?test1=danger")
        response1 = middleware(request1)
        assert response1.status_code == 403

        # Second rule should block
        request2 = factory.get("/echo?test2=evil")
        response2 = middleware(request2)
        assert response2.status_code == 403

        # Neither rule matches, should pass
        request3 = factory.get("/echo?test3=safe")
        response3 = middleware(request3)
        assert response3.status_code == 200


def test_request_body_inspection():
    """Test inspection of request body content."""
    from django.http import JsonResponse
    from django.test import RequestFactory, override_settings

    from lewaf.integrations.django import LeWAFMiddleware, reset_waf

    with override_settings(
        LEWAF_CONFIG={
            "rules": [
                'SecRule REQUEST_BODY "@rx malicious" "id:3020,phase:2,deny,log"'
            ]
        }
    ):
        reset_waf()

        factory = RequestFactory()

        def get_response(req):
            return JsonResponse({"message": "OK"})

        middleware = LeWAFMiddleware(get_response)

        # Normal body should pass
        normal_request = factory.post(
            "/api/data",
            data="normal content",
            content_type="text/plain",
        )
        normal_response = middleware(normal_request)
        assert normal_response.status_code == 200

        # Malicious body should be blocked
        malicious_request = factory.post(
            "/api/data",
            data="this is malicious content",
            content_type="text/plain",
        )
        malicious_response = middleware(malicious_request)
        assert malicious_response.status_code == 403


def test_case_sensitivity_handling():
    """Test case sensitivity in rule matching."""
    from django.http import JsonResponse
    from django.test import RequestFactory, override_settings

    from lewaf.integrations.django import LeWAFMiddleware, reset_waf

    with override_settings(
        LEWAF_CONFIG={
            "rules": ['SecRule ARGS:test "@rx ATTACK" "id:3015,phase:2,deny,log,t:uppercase"']
        }
    ):
        reset_waf()

        factory = RequestFactory()

        def get_response(req):
            return JsonResponse({"message": "OK"})

        middleware = LeWAFMiddleware(get_response)

        # Lowercase attack should be caught due to uppercase transformation
        request = factory.get("/echo?test=attack")
        response = middleware(request)
        assert response.status_code == 403


def test_transaction_isolation():
    """Test that requests have isolated transactions."""
    from django.http import JsonResponse
    from django.test import RequestFactory, override_settings

    from lewaf.integrations.django import LeWAFMiddleware, reset_waf

    with override_settings(
        LEWAF_CONFIG={
            "rules": ['SecRule ARGS:block "@rx yes" "id:3017,phase:1,deny,log"']
        }
    ):
        reset_waf()

        factory = RequestFactory()

        def get_response(req):
            return JsonResponse({"message": "OK"})

        middleware = LeWAFMiddleware(get_response)

        # One blocked, one allowed
        blocked_request = factory.get("/echo?block=yes")
        blocked_response = middleware(blocked_request)

        allowed_request = factory.get("/echo?block=no")
        allowed_response = middleware(allowed_request)

        assert blocked_response.status_code == 403
        assert allowed_response.status_code == 200


def test_error_handling():
    """Test middleware error handling."""
    from django.http import JsonResponse
    from django.test import RequestFactory

    from lewaf.integrations.django import LeWAFMiddleware, reset_waf

    reset_waf()

    factory = RequestFactory()

    def get_response(req):
        return JsonResponse({"message": "OK"})

    middleware = LeWAFMiddleware(get_response)

    # Should not crash with unusual inputs
    request = factory.get("/", HTTP_HOST="test.example.com")
    response = middleware(request)
    assert response.status_code != 500


def test_custom_block_response():
    """Test custom block response configuration."""
    from django.http import JsonResponse
    from django.test import RequestFactory, override_settings

    from lewaf.integrations.django import LeWAFMiddleware, reset_waf

    with override_settings(
        LEWAF_BLOCK_STATUS=429,
        LEWAF_BLOCK_MESSAGE="Rate limited",
        LEWAF_CONFIG={
            "rules": ['SecRule ARGS "@rx blocked" "id:3004,phase:2,deny"']
        }
    ):
        reset_waf()

        factory = RequestFactory()

        def get_response(req):
            return JsonResponse({"message": "OK"})

        middleware = LeWAFMiddleware(get_response)

        request = factory.get("/?test=blocked")
        response = middleware(request)

        assert response.status_code == 429


def test_get_waf_singleton():
    """Test that get_waf returns singleton instance."""
    from lewaf.integrations.django import get_waf, reset_waf

    reset_waf()

    waf1 = get_waf()
    waf2 = get_waf()

    assert waf1 is waf2


def test_reset_waf():
    """Test that reset_waf clears the singleton."""
    from lewaf.integrations.django import get_waf, reset_waf

    waf1 = get_waf()
    reset_waf()
    waf2 = get_waf()

    # After reset, should be a new instance
    assert waf1 is not waf2
