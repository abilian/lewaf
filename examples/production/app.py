"""
Production-ready LeWAF application example.

This example shows how to deploy LeWAF with:
- CRS rules loaded (594 rules)
- Monitoring and metrics
- Health checks
- Proper logging
- Error handling
"""

import logging
import time
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from lewaf.integrations.starlette import WAFMiddleware

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
    # Rule engine mode
    # "DetectionOnly" - Log only, don't block
    # "On" - Block malicious requests
    "engine": "DetectionOnly",  # Start in detection mode for testing
    # Load CRS rules (594 rules)
    "rule_files": [
        str(Path(__file__).parent.parent.parent / "coraza.conf"),
    ],
    # Request limits
    "request_body_limit": 13107200,  # 12.5 MB
    # Custom rules (optional)
    "custom_rules": [
        # Example: Block admin parameter
        'SecRule ARGS:admin "@rx ^true$" "id:9001,phase:1,deny,msg:\'Admin access forbidden\'"',
    ],
}


# Application routes
async def homepage(request):
    """Homepage endpoint."""
    return PlainTextResponse("Hello! This application is protected by LeWAF.")


async def api_users(request):
    """Example API endpoint."""
    return JSONResponse(
        {
            "users": [
                {"id": 1, "name": "Alice"},
                {"id": 2, "name": "Bob"},
            ]
        }
    )


async def health_check(request):
    """Health check endpoint for monitoring."""
    uptime = time.time() - START_TIME

    return JSONResponse(
        {
            "status": "healthy",
            "service": "lewaf-protected-app",
            "uptime_seconds": uptime,
            "waf_status": "active",
        }
    )


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

    return JSONResponse(
        {
            "uptime_seconds": uptime,
            "waf": waf_stats,
            "app": {
                "version": "1.0.0",
                "environment": "production",
            },
        }
    )


# Create application with WAF middleware
middleware = [
    Middleware(WAFMiddleware, config=WAF_CONFIG),
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
logger.info(f"WAF mode: {WAF_CONFIG['engine']}")
logger.info(f"Loading rules from: {WAF_CONFIG['rule_files']}")


if __name__ == "__main__":
    import uvicorn

    # Run with uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
