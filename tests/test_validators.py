"""Unit tests for sounding.validators — no network or Docker needed."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from sounding.validators import (
    is_internal_ip,
    sanitize_domain,
    validate_host,
    validate_port,
    validate_subnet,
    validate_url,
)


# ── validate_host ──────────────────────────────────────────────────────────


class TestValidateHost:
    def test_valid_hostname(self):
        assert validate_host("example.com") == "example.com"

    def test_valid_ip(self):
        assert validate_host("1.2.3.4") == "1.2.3.4"

    def test_valid_ipv6(self):
        assert validate_host("::1") == "::1"

    def test_strips_whitespace(self):
        assert validate_host("  example.com  ") == "example.com"

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_host("")

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_host("example.com; rm -rf /")

    def test_rejects_pipe(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_host("example.com | cat /etc/passwd")

    def test_rejects_backtick(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_host("`whoami`.example.com")

    def test_rejects_dollar(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_host("$(whoami).example.com")

    def test_rejects_ampersand(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_host("example.com & echo pwned")

    def test_rejects_newline(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_host("example.com\n; echo pwned")

    def test_localhost(self):
        assert validate_host("localhost") == "localhost"

    def test_subdomain(self):
        assert validate_host("sub.domain.example.com") == "sub.domain.example.com"


# ── validate_url ───────────────────────────────────────────────────────────


class TestValidateUrl:
    def test_http(self):
        assert validate_url("http://example.com") == "http://example.com"

    def test_https(self):
        assert validate_url("https://example.com/path") == "https://example.com/path"

    def test_rejects_file(self):
        with pytest.raises(ValueError, match="not allowed"):
            validate_url("file:///etc/passwd")

    def test_rejects_ftp(self):
        with pytest.raises(ValueError, match="not allowed"):
            validate_url("ftp://example.com")

    def test_rejects_no_scheme(self):
        with pytest.raises(ValueError, match="must include a scheme"):
            validate_url("example.com")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_url("")

    def test_rejects_javascript(self):
        with pytest.raises(ValueError):
            validate_url("javascript:alert(1)")

    def test_strips_whitespace(self):
        assert validate_url("  https://example.com  ") == "https://example.com"


# ── validate_subnet ────────────────────────────────────────────────────────


class TestValidateSubnet:
    def test_private_192(self):
        assert validate_subnet("192.168.1.0/24") == "192.168.1.0/24"

    def test_private_10(self):
        assert validate_subnet("10.0.0.0/24") == "10.0.0.0/24"

    def test_private_172(self):
        assert validate_subnet("172.16.0.0/24") == "172.16.0.0/24"

    def test_rejects_public(self):
        with pytest.raises(ValueError, match="not within RFC 1918"):
            validate_subnet("8.8.8.0/24")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_subnet("")

    def test_rejects_garbage(self):
        with pytest.raises(ValueError, match="Invalid subnet"):
            validate_subnet("not-a-subnet")

    def test_rejects_172_32(self):
        """172.32.x.x is outside the 172.16-31 private range."""
        with pytest.raises(ValueError, match="not within RFC 1918"):
            validate_subnet("172.32.0.0/24")


# ── validate_port ──────────────────────────────────────────────────────────


class TestValidatePort:
    def test_valid_port(self):
        assert validate_port(80) is True

    def test_port_1(self):
        assert validate_port(1) is True

    def test_port_65535(self):
        assert validate_port(65535) is True

    def test_port_0(self):
        assert validate_port(0) is False

    def test_port_negative(self):
        assert validate_port(-1) is False

    def test_port_too_high(self):
        assert validate_port(65536) is False

    def test_port_string(self):
        assert validate_port("80") is False  # type: ignore


# ── sanitize_domain ────────────────────────────────────────────────────────


class TestSanitizeDomain:
    def test_basic(self):
        assert sanitize_domain("Example.COM") == "example.com"

    def test_strips_whitespace(self):
        assert sanitize_domain("  example.com  ") == "example.com"

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            sanitize_domain("example.com; rm -rf /")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            sanitize_domain("")

    def test_rejects_backtick(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            sanitize_domain("`whoami`.com")


# ── is_internal_ip ────────────────────────────────────────────────────────


class TestIsInternalIp:
    """Verify that all blocked IP ranges are correctly identified."""

    def test_loopback_127_0_0_1(self):
        assert is_internal_ip("127.0.0.1") is True

    def test_loopback_127_x(self):
        assert is_internal_ip("127.255.255.255") is True

    def test_rfc1918_10_x(self):
        assert is_internal_ip("10.0.0.1") is True

    def test_rfc1918_10_255(self):
        assert is_internal_ip("10.255.255.255") is True

    def test_rfc1918_172_16(self):
        assert is_internal_ip("172.16.0.1") is True

    def test_rfc1918_172_31(self):
        assert is_internal_ip("172.31.255.255") is True

    def test_rfc1918_192_168(self):
        assert is_internal_ip("192.168.1.1") is True

    def test_link_local(self):
        assert is_internal_ip("169.254.1.1") is True

    def test_cloud_metadata(self):
        assert is_internal_ip("169.254.169.254") is True

    def test_unspecified(self):
        assert is_internal_ip("0.0.0.0") is True

    def test_ipv6_loopback(self):
        assert is_internal_ip("::1") is True

    def test_public_ip_not_internal(self):
        assert is_internal_ip("8.8.8.8") is False

    def test_public_ip_1_1_1_1(self):
        assert is_internal_ip("1.1.1.1") is False

    def test_172_32_not_private(self):
        """172.32.x.x is outside the 172.16-31 private range."""
        assert is_internal_ip("172.32.0.1") is False

    def test_invalid_string(self):
        assert is_internal_ip("not-an-ip") is False


# ── validate_url SSRF blocking ────────────────────────────────────────────


class TestValidateUrlSsrf:
    """SSRF protection: validate_url must block internal/private targets."""

    def test_blocks_loopback_ip(self):
        with pytest.raises(ValueError, match="internal"):
            validate_url("http://127.0.0.1/admin")

    def test_blocks_rfc1918_10(self):
        with pytest.raises(ValueError, match="internal"):
            validate_url("http://10.0.0.1/")

    def test_blocks_rfc1918_172(self):
        with pytest.raises(ValueError, match="internal"):
            validate_url("http://172.16.0.1:8080/")

    def test_blocks_rfc1918_192_168(self):
        with pytest.raises(ValueError, match="internal"):
            validate_url("http://192.168.1.1/")

    def test_blocks_link_local(self):
        with pytest.raises(ValueError, match="internal"):
            validate_url("http://169.254.1.1/")

    def test_blocks_cloud_metadata(self):
        with pytest.raises(ValueError, match="internal"):
            validate_url("http://169.254.169.254/latest/meta-data/")

    def test_blocks_zero_ip(self):
        with pytest.raises(ValueError, match="internal"):
            validate_url("http://0.0.0.0/")

    def test_blocks_localhost_hostname(self):
        """localhost resolves to 127.0.0.1 — should be blocked."""
        with pytest.raises(ValueError, match="internal"):
            validate_url("http://localhost/admin")

    def test_allows_public_url(self):
        """Public URLs should pass validation."""
        # Mock DNS resolution to return a public IP so test doesn't hit network
        with patch("sounding.validators.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (2, 1, 6, "", ("93.184.216.34", 0)),
            ]
            result = validate_url("http://example.com/")
            assert result == "http://example.com/"

    def test_blocks_hostname_resolving_to_internal(self):
        """A hostname that resolves to a private IP should be blocked."""
        with patch("sounding.validators.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (2, 1, 6, "", ("10.0.0.1", 0)),
            ]
            with pytest.raises(ValueError, match="internal"):
                validate_url("http://evil.example.com/")


# ── validate_host allow_internal=False ────────────────────────────────────


class TestValidateHostSsrf:
    """validate_host with allow_internal=False for SSRF protection."""

    def test_blocks_loopback(self):
        with pytest.raises(ValueError, match="internal"):
            validate_host("127.0.0.1", allow_internal=False)

    def test_blocks_private_10(self):
        with pytest.raises(ValueError, match="internal"):
            validate_host("10.0.0.1", allow_internal=False)

    def test_blocks_private_172(self):
        with pytest.raises(ValueError, match="internal"):
            validate_host("172.16.0.1", allow_internal=False)

    def test_blocks_private_192(self):
        with pytest.raises(ValueError, match="internal"):
            validate_host("192.168.0.1", allow_internal=False)

    def test_blocks_link_local(self):
        with pytest.raises(ValueError, match="internal"):
            validate_host("169.254.169.254", allow_internal=False)

    def test_blocks_ipv6_loopback(self):
        with pytest.raises(ValueError, match="internal"):
            validate_host("::1", allow_internal=False)

    def test_allows_internal_by_default(self):
        """Default allow_internal=True should not block internal IPs."""
        assert validate_host("127.0.0.1") == "127.0.0.1"
        assert validate_host("10.0.0.1") == "10.0.0.1"
        assert validate_host("::1") == "::1"

    def test_allows_public_ip(self):
        assert validate_host("8.8.8.8", allow_internal=False) == "8.8.8.8"

    def test_blocks_hostname_resolving_to_internal(self):
        with patch("sounding.validators.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (2, 1, 6, "", ("192.168.1.1", 0)),
            ]
            with pytest.raises(ValueError, match="internal"):
                validate_host("evil.local", allow_internal=False)
