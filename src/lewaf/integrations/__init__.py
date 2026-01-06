"""LeWAF integrations for various web frameworks.

Available integrations:

    Starlette/FastAPI (ASGI):
        from lewaf.integrations.starlette import LeWAFMiddleware

    Flask (WSGI):
        from lewaf.integrations.flask import FlaskWAFMiddleware

    Django:
        Add 'lewaf.integrations.django.LeWAFMiddleware' to MIDDLEWARE

See individual module docstrings for detailed usage examples.
"""
