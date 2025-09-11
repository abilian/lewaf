"""Command-line interface for Coraza reverse proxy."""

from __future__ import annotations

import argparse
import logging
import sys

import uvicorn

from .server import create_proxy_app


def setup_logging(level: str = "INFO") -> None:
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def load_rules_from_file(file_path: str) -> list[str]:
    """Load WAF rules from a configuration file."""
    rules = []
    try:
        with open(file_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    rules.append(line)
    except FileNotFoundError:
        logging.error(f"Rules file not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error loading rules from {file_path}: {e}")
        sys.exit(1)

    return rules


def main() -> None:
    """Main entry point for the Coraza reverse proxy CLI."""
    parser = argparse.ArgumentParser(
        description="Coraza WAF Reverse Proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic proxy
  python -m coraza_poc.proxy.cli --upstream http://backend:8000

  # With custom rules file
  python -m coraza_poc.proxy.cli --upstream http://backend:8000 --rules-file waf.conf

  # Custom host and port
  python -m coraza_poc.proxy.cli --upstream http://backend:8000 --host 0.0.0.0 --port 8080
        """,
    )

    parser.add_argument(
        "--upstream",
        required=True,
        help="Upstream server URL (e.g., http://backend:8000)",
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the proxy server (default: 127.0.0.1)",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to bind the proxy server (default: 8080)",
    )

    parser.add_argument(
        "--rules-file",
        help="Path to WAF rules configuration file",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Upstream request timeout in seconds (default: 30.0)",
    )

    parser.add_argument(
        "--max-connections",
        type=int,
        default=100,
        help="Maximum number of upstream connections (default: 100)",
    )

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Log level (default: INFO)",
    )

    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)",
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)

    logger = logging.getLogger(__name__)
    logger.info("Starting Coraza reverse proxy")
    logger.info(f"Upstream: {args.upstream}")
    logger.info(f"Listening on: {args.host}:{args.port}")

    # Load WAF rules
    waf_rules: list[str] | None = None
    if args.rules_file:
        waf_rules = load_rules_from_file(args.rules_file)
        logger.info(f"Loaded {len(waf_rules)} WAF rules from {args.rules_file}")

    # Proxy configuration
    proxy_config = {
        "timeout": args.timeout,
        "max_connections": args.max_connections,
    }

    # Create application
    app = create_proxy_app(
        upstream_url=args.upstream,
        waf_rules=waf_rules,
        **proxy_config,
    )

    # Run server
    try:
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            workers=args.workers,
            reload=args.reload,
            log_level=args.log_level.lower(),
        )
    except KeyboardInterrupt:
        logger.info("Shutting down proxy server...")
    except Exception as e:
        logger.error(f"Error starting server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
