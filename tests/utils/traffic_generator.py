"""Traffic generation for load testing."""

import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lewaf.integration import WAF

from tests.utils.metrics_collector import MetricsCollector


class TrafficGenerator:
    """Generate realistic HTTP traffic for load testing."""

    def __init__(self, waf: "WAF", concurrency: int = 10):
        """Initialize traffic generator.

        Args:
            waf: WAF instance to test
            concurrency: Number of concurrent workers
        """
        self.waf = waf
        self.concurrency = concurrency
        self.metrics = MetricsCollector()

    def generate_request(self) -> dict[str, Any]:
        """Generate a realistic HTTP request.

        Returns:
            Request dictionary with method, URI, headers, body
        """
        methods = ["GET", "POST", "PUT", "DELETE"]
        method = random.choice(methods)

        # Generate URI
        resource_id = random.randint(1, 1000)
        uris = [
            f"/api/users/{resource_id}",
            f"/api/products/{resource_id}",
            "/api/search?q=test",
            "/api/dashboard",
            "/health",
        ]
        uri = random.choice(uris)

        # Generate headers
        headers = {
            "User-Agent": "LoadTest/1.0",
            "Accept": "application/json",
            "Host": "example.com",
        }

        # Generate body for POST/PUT
        body = None
        content_type = None
        if method in ["POST", "PUT"]:
            body_type = random.choice(["json", "urlencoded", "empty"])
            if body_type == "json":
                body = f'{{"id": {resource_id}, "name": "test", "value": {random.random()}}}'
                content_type = "application/json"
            elif body_type == "urlencoded":
                body = f"id={resource_id}&name=test&value={random.random()}"
                content_type = "application/x-www-form-urlencoded"

        return {
            "method": method,
            "uri": uri,
            "headers": headers,
            "body": body,
            "content_type": content_type,
        }

    def _process_single_request(self, request: dict[str, Any]) -> tuple[float, bool]:
        """Process a single request through WAF.

        Args:
            request: Request dictionary

        Returns:
            Tuple of (latency_ms, error)
        """
        start = time.time()
        error = False

        try:
            tx = self.waf.new_transaction()

            # Process request
            tx.process_uri(request["uri"], request["method"])

            # Add headers
            for name, value in request["headers"].items():
                tx.variables.request_headers.add(name.lower(), value)

            # Process headers
            tx.process_request_headers()

            # Process body if present
            if request["body"]:
                tx.add_request_body(
                    request["body"].encode("utf-8"), request.get("content_type", "")
                )
                tx.process_request_body()

        except Exception:
            error = True

        latency_ms = (time.time() - start) * 1000
        return latency_ms, error

    def _worker(self, num_requests: int) -> None:
        """Worker thread to process requests.

        Args:
            num_requests: Number of requests to process
        """
        for _ in range(num_requests):
            request = self.generate_request()
            latency, error = self._process_single_request(request)
            self.metrics.record_request(latency, error)

    def run(
        self, total_requests: int = 1000, duration_sec: int | None = None
    ) -> dict[str, Any]:
        """Run load test.

        Args:
            total_requests: Total number of requests to send
            duration_sec: Duration to run (overrides total_requests if set)

        Returns:
            Metrics summary dictionary
        """
        self.metrics = MetricsCollector()
        self.metrics.start()

        if duration_sec:
            # Duration-based test
            self._run_duration_based(duration_sec)
        else:
            # Request count-based test
            self._run_count_based(total_requests)

        self.metrics.stop()
        return self.metrics.get_summary()

    def _run_count_based(self, total_requests: int) -> None:
        """Run test for specific number of requests.

        Args:
            total_requests: Total requests to send
        """
        requests_per_worker = total_requests // self.concurrency
        remainder = total_requests % self.concurrency

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = []

            # Submit workers
            for i in range(self.concurrency):
                num_requests = requests_per_worker + (1 if i < remainder else 0)
                futures.append(executor.submit(self._worker, num_requests))

            # Wait for completion
            for future in as_completed(futures):
                future.result()

    def _run_duration_based(self, duration_sec: int) -> None:
        """Run test for specific duration.

        Args:
            duration_sec: Duration in seconds
        """
        end_time = time.time() + duration_sec
        requests_sent = 0

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = []

            while time.time() < end_time:
                # Submit batch of requests
                batch_size = self.concurrency * 10
                for _ in range(batch_size):
                    if time.time() >= end_time:
                        break

                    request = self.generate_request()
                    future = executor.submit(self._process_single_request, request)
                    futures.append(future)
                    requests_sent += 1

                # Process completed futures
                done_futures = []
                for future in futures:
                    if future.done():
                        latency, error = future.result()
                        self.metrics.record_request(latency, error)
                        done_futures.append(future)

                # Remove completed futures
                for future in done_futures:
                    futures.remove(future)

            # Wait for remaining futures
            for future in as_completed(futures):
                latency, error = future.result()
                self.metrics.record_request(latency, error)
