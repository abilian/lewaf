"""Sample ASGI application with LeWAF middleware.

This demonstrates how to integrate LeWAF with Starlette/FastAPI applications.

Run with:
    uvicorn examples.asgi_demo:app --reload
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from lewaf.integration.asgi import ASGIMiddleware

# Sample application routes


async def homepage(request):
    """Homepage with test links."""
    html = """
    <html>
        <head><title>LeWAF ASGI Demo</title></head>
        <body>
            <h1>LeWAF ASGI Middleware Demo</h1>
            <p>Try these endpoints to test WAF protection:</p>
            <ul>
                <li><a href="/safe">Safe endpoint</a></li>
                <li><a href="/api/user?id=123">API with safe parameter</a></li>
                <li><a href="/api/user?id=<script>">API with XSS attack (blocked)</a></li>
                <li><a href="/admin">Admin page (blocked)</a></li>
                <li>
                    <form method="post" action="/api/submit">
                        <input name="comment" value="Normal comment">
                        <button>Submit safe form</button>
                    </form>
                </li>
                <li>
                    <form method="post" action="/api/submit">
                        <input name="comment" value="<script>alert('xss')</script>">
                        <button>Submit malicious form (blocked)</button>
                    </form>
                </li>
            </ul>
        </body>
    </html>
    """
    return HTMLResponse(html)


async def safe_endpoint(request):
    """Safe endpoint."""
    return JSONResponse({"status": "success", "message": "This is a safe endpoint"})


async def api_user(request):
    """API endpoint with parameters."""
    user_id = request.query_params.get("id", "unknown")
    return JSONResponse({"user_id": user_id, "name": f"User {user_id}"})


async def admin_endpoint(request):
    """Admin endpoint (should be blocked by WAF)."""
    return JSONResponse({"message": "Admin access granted"})


async def api_submit(request):
    """API endpoint accepting POST data."""
    form = await request.form()
    comment = form.get("comment", "")
    return JSONResponse({
        "status": "success",
        "comment_received": comment,
        "length": len(comment),
    })


# Create Starlette application
routes = [
    Route("/", homepage),
    Route("/safe", safe_endpoint),
    Route("/api/user", api_user),
    Route("/admin", admin_endpoint),
    Route("/api/submit", api_submit, methods=["POST"]),
]

app = Starlette(routes=routes)

# Wrap with LeWAF middleware
# Using simple inline configuration
waf_config = {
    "rules": [
        'SecRule ARGS "@rx <script" "id:1,deny,msg:XSS Attack Detected"',
        'SecRule REQUEST_URI "@rx /admin" "id:2,deny,msg:Admin Access Blocked"',
        'SecRule ARGS "@rx union.*select" "id:3,deny,msg:SQL Injection Detected"',
    ],
}

app = ASGIMiddleware(app, config_dict=waf_config)

# Alternative: Load from config file
# app = ASGIMiddleware(app, config_file="config/examples/quickstart.yaml")

# Alternative: Enable hot-reload
# app = ASGIMiddleware(
#     app,
#     config_file="config/examples/development.yaml",
#     enable_hot_reload=True
# )

if __name__ == "__main__":
    import uvicorn

    print("Starting LeWAF ASGI demo...")
    print("Visit http://localhost:8000 to test the WAF")
    uvicorn.run(app, host="0.0.0.0", port=8000)
