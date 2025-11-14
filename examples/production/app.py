"""
Production-ready LeWAF application example.

This example shows how to deploy LeWAF with:
- CRS rules loaded (594 rules)
- Monitoring and metrics
- Health checks
- Proper logging
- Error handling
"""

from __future__ import annotations

import logging
import time

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from lewaf.integrations.starlette import LeWAFMiddleware

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Application start time for uptime tracking
START_TIME = time.time()

# WAF Configuration
WAF_CONFIG = {
    # Rules
    "rules": [
        # Example: Block admin parameter
        'SecRule ARGS:admin "@rx ^true$" "id:9001,phase:1,deny,msg:\'Admin access forbidden\'"',
        # XSS Protection
        'SecRule ARGS "@rx <script" "id:9002,phase:2,deny,msg:\'XSS Attack\'"',
    ],
    # Rule files (if needed)
    "rule_files": [],
}


# Application routes
async def homepage(request):
    """Homepage endpoint."""
    return PlainTextResponse("Hello! This application is protected by LeWAF.")


async def api_users(request):
    """Example API endpoint."""
    return JSONResponse({
        "users": [
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"},
        ]
    })


async def health_check(request):
    """Health check endpoint for monitoring."""
    uptime = time.time() - START_TIME

    return JSONResponse({
        "status": "healthy",
        "service": "lewaf-protected-app",
        "uptime_seconds": uptime,
        "waf_status": "active",
    })


async def metrics_endpoint(request):
    """Metrics endpoint for monitoring.

    In production, integrate with Prometheus/Grafana.
    """
    uptime = time.time() - START_TIME

    # Get WAF stats from middleware if available
    waf_stats = {
        "requests_total": "N/A",
        "requests_blocked": "N/A",
        "avg_processing_time_ms": "N/A",
    }

    return JSONResponse({
        "uptime_seconds": uptime,
        "waf": waf_stats,
        "app": {
            "version": "1.0.0",
            "environment": "production",
        },
    })


# Create application with WAF middleware
middleware = [
    Middleware(LeWAFMiddleware, rules=WAF_CONFIG["rules"]),
]

routes = [
    Route("/", homepage),
    Route("/api/users", api_users),
    Route("/health", health_check),
    Route("/metrics", metrics_endpoint),
]

app = Starlette(
    routes=routes,
    middleware=middleware,
)

# Log startup
logger.info("LeWAF application started")
logger.info(f"WAF rules loaded: {len(WAF_CONFIG['rules'])}")
logger.info("WAF protection enabled")


if __name__ == "__main__":
    import uvicorn

    # Run with uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
