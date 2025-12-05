"""
FastAPI advanced integration example for LeWAF.

This example shows advanced FastAPI integration with:
- Custom middleware
- Dependency injection
- Response models
- OpenAPI documentation
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from lewaf.integration import WAF


# Pydantic models
class User(BaseModel):
    id: int
    name: str
    email: str | None = None


class SearchRequest(BaseModel):
    query: str
    limit: int = 10


class SearchResponse(BaseModel):
    query: str
    results: list[str]
    total: int


# WAF Configuration
WAF_CONFIG = {
    "rules": [
        'SecRule ARGS:admin "@rx ^true$" "id:9001,phase:1,deny,msg:\'Admin access forbidden\'"',
        'SecRule ARGS "@rx <script" "id:9002,phase:2,deny,msg:\'XSS Attack\'"',
    ],
    "rule_files": [],
}


# Custom WAF Middleware
class LeWAFMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for LeWAF integration.

    This middleware processes all requests and responses through LeWAF.
    """

    def __init__(self, app, waf_config: dict):
        super().__init__(app)
        self.waf = WAF(waf_config)

    async def dispatch(self, request: Request, call_next):
        # Create WAF transaction
        tx = self.waf.new_transaction()

        # Set URI and method
        uri = str(request.url.path) + (
            "?" + str(request.url.query) if request.url.query else ""
        )
        tx.process_uri(uri, request.method)

        # Add request headers
        for key, value in request.headers.items():
            tx.variables.request_headers.add(key.lower(), value)

        # Process Phase 1 (request headers)
        tx.process_request_headers()

        # Check for interruption after headers
        if tx.interruption:
            return self._blocked_response(tx)

        # Process request body if present
        if request.method in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            if body:
                content_type = request.headers.get("content-type", "")
                tx.add_request_body(body, content_type)
                tx.process_request_body()

                # Check for interruption after body
                if tx.interruption:
                    return self._blocked_response(tx)

        # Get response
        response = await call_next(request)

        # Add response status
        tx.add_response_status(response.status_code)

        # Add response headers
        for key, value in response.headers.items():
            tx.add_response_headers({key.lower(): value})

        # Process Phase 3 (response headers)
        tx.process_response_headers()

        # Note: Processing response body in middleware is tricky with streaming responses
        # For production, consider implementing response body inspection differently

        return response

    def _blocked_response(self, tx):
        """Generate a blocked response."""
        return JSONResponse(
            {
                "error": "Request blocked by WAF",
                "rule_id": tx.interruption.get("rule_id") if tx.interruption else None,
                "message": tx.interruption.get("action", "Unknown")
                if tx.interruption
                else "Unknown",
            },
            status_code=403,
        )


# FastAPI application
app = FastAPI(
    title="LeWAF Protected API",
    description="FastAPI application with LeWAF integration",
    version="1.0.0",
)

# Add WAF middleware
app.add_middleware(LeWAFMiddleware, waf_config=WAF_CONFIG)


# Dependency for WAF transaction (optional)
async def get_waf_transaction(request: Request):
    """
    Dependency that provides access to WAF transaction.

    This can be used in route handlers to access WAF information.
    """
    # In a real implementation, you would store the transaction in request.state
    # during middleware processing
    return getattr(request.state, "waf_transaction", None)


# Routes
@app.get("/")
async def home():
    """Home page."""
    return {"message": "Hello from FastAPI with LeWAF protection!"}


@app.get("/api/users", response_model=list[User])
async def get_users():
    """
    Get list of users.

    This endpoint returns a list of all users.
    """
    return [
        User(id=1, name="Alice", email="alice@example.com"),
        User(id=2, name="Bob", email="bob@example.com"),
        User(id=3, name="Charlie", email="charlie@example.com"),
    ]


@app.get("/api/users/{user_id}", response_model=User)
async def get_user(user_id: int):
    """
    Get user by ID.

    Args:
        user_id: The user ID to retrieve

    Raises:
        HTTPException: If user not found
    """
    # Mock user lookup
    if user_id == 1:
        return User(id=1, name="Alice", email="alice@example.com")
    raise HTTPException(status_code=404, detail="User not found")


@app.post("/api/search", response_model=SearchResponse)
async def search(search_request: SearchRequest):
    """
    Search endpoint.

    This endpoint performs a search based on the provided query.
    """
    return SearchResponse(
        query=search_request.query,
        results=["result1", "result2", "result3"],
        total=3,
    )


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "fastapi-lewaf",
        "waf_enabled": True,
    }


@app.get("/metrics")
async def metrics():
    """
    Metrics endpoint.

    Returns application and WAF metrics.
    """
    # In production, integrate with Prometheus
    return {
        "requests_total": "N/A",
        "requests_blocked": "N/A",
        "waf_rules_loaded": 594,
    }


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )


if __name__ == "__main__":
    import uvicorn

    # Run application
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
