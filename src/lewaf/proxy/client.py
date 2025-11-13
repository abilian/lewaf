"""HTTP client for proxying requests to upstream servers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import httpx
from starlette.responses import StreamingResponse

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.requests import Request

logger = logging.getLogger(__name__)


class ProxyClient:
    """HTTP client for proxying requests to upstream servers."""

    def __init__(
        self,
        upstream_url: str,
        timeout: float = 30.0,
        follow_redirects: bool = False,
        verify_ssl: bool = True,
        max_connections: int = 100,
        max_keepalive_connections: int = 20,
    ):
        """Initialize proxy client.

        Args:
            upstream_url: Base URL of the upstream server
            timeout: Request timeout in seconds
            follow_redirects: Whether to follow redirects
            verify_ssl: Whether to verify SSL certificates
            max_connections: Maximum number of connections
            max_keepalive_connections: Maximum number of keepalive connections
        """
        self.upstream_url = upstream_url.rstrip("/")
        self.upstream_parsed = urlparse(self.upstream_url)

        # Configure httpx client
        limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
        )

        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=follow_redirects,
            verify=verify_ssl,
            limits=limits,
        )

    async def proxy_request(self, request: Request) -> StreamingResponse:
        """Proxy an incoming request to the upstream server.

        Args:
            request: The incoming Starlette request

        Returns:
            StreamingResponse with the upstream response
        """
        # Build upstream URL
        upstream_path = str(request.url.path)
        if request.url.query:
            upstream_path += f"?{request.url.query}"

        upstream_url = urljoin(self.upstream_url + "/", upstream_path.lstrip("/"))

        # Prepare headers (exclude hop-by-hop headers)
        headers = self._filter_headers(dict(request.headers))

        # Add X-Forwarded headers
        headers.update(self._get_forwarded_headers(request))

        # Read request body if present
        body = None
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()

        try:
            logger.debug(f"Proxying {request.method} {upstream_url}")

            # Make upstream request
            upstream_response = await self.client.request(
                method=request.method,
                url=upstream_url,
                headers=headers,
                content=body,
            )

            # Filter response headers
            response_headers = self._filter_response_headers(
                dict(upstream_response.headers)
            )

            # Create streaming response
            return StreamingResponse(
                content=self._stream_content(upstream_response),
                status_code=upstream_response.status_code,
                headers=response_headers,
                media_type=upstream_response.headers.get("content-type"),
            )

        except httpx.RequestError as e:
            logger.error("Error proxying request to %s: %s", upstream_url, e)
            return StreamingResponse(
                content=iter([b"Bad Gateway"]),
                status_code=502,
                media_type="text/plain",
            )
        except httpx.HTTPStatusError as e:
            logger.error("HTTP error from upstream %s: %s", upstream_url, e)
            # Return the error response from upstream
            response_headers = self._filter_response_headers(dict(e.response.headers))
            return StreamingResponse(
                content=iter([e.response.content]),
                status_code=e.response.status_code,
                headers=response_headers,
            )

    async def _stream_content(self, response: httpx.Response) -> AsyncIterator[bytes]:
        """Stream response content from upstream."""
        async for chunk in response.aiter_bytes():
            yield chunk

    def _filter_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Filter out hop-by-hop headers that shouldn't be forwarded."""
        hop_by_hop_headers = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
            "host",  # Will be set by httpx
        }

        return {k: v for k, v in headers.items() if k.lower() not in hop_by_hop_headers}

    def _filter_response_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Filter response headers that shouldn't be forwarded."""
        hop_by_hop_headers = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        }

        return {k: v for k, v in headers.items() if k.lower() not in hop_by_hop_headers}

    def _get_forwarded_headers(self, request: Request) -> dict[str, str]:
        """Generate X-Forwarded headers for the upstream request."""
        headers = {}

        if request.client:
            headers["X-Forwarded-For"] = request.client.host
            headers["X-Forwarded-Port"] = str(request.client.port)

        headers["X-Forwarded-Proto"] = request.url.scheme
        headers["X-Forwarded-Host"] = request.url.netloc

        return headers

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
