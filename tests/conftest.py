"""Sounding MCP server test fixtures.

Spins up throwaway network targets via Docker Compose for integration tests.
Run `docker compose -f tests/docker-compose.test.yml up -d` before running tests,
or use the `test_targets` fixture which handles lifecycle automatically.
"""

import logging
import os
import subprocess
import time

import pytest

logger = logging.getLogger(__name__)

# Test target addresses — match docker-compose.test.yml ports
WEB_TARGET = os.getenv("SOUNDING_TEST_WEB", "localhost:18080")
SSL_TARGET = os.getenv("SOUNDING_TEST_SSL", "localhost:18443")
DNS_TARGET = os.getenv("SOUNDING_TEST_DNS", "localhost:15353")

COMPOSE_FILE = os.path.join(os.path.dirname(__file__), "docker-compose.test.yml")


@pytest.fixture(scope="session")
def test_targets():
    """Start Docker Compose test targets for the full test session.

    If Docker Compose fails to start, the fixture still yields so that
    tests relying only on web-target or dns-target can proceed. Tests
    that need a specific target should check availability themselves.
    """
    if os.getenv("SOUNDING_SKIP_DOCKER"):
        yield  # Targets already running (e.g., CI service containers)
        return

    try:
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "up", "-d", "--wait"],
            check=True,
            capture_output=True,
            timeout=60,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("Docker Compose start failed: %s — integration tests may be skipped", exc)
    yield
    try:
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "down", "-v"],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass


@pytest.fixture
def web_target(test_targets):
    """HTTP target address."""
    return WEB_TARGET


@pytest.fixture
def ssl_target(test_targets):
    """HTTPS target address (self-signed cert)."""
    return SSL_TARGET


@pytest.fixture
def dns_target(test_targets):
    """DNS target address."""
    return DNS_TARGET
