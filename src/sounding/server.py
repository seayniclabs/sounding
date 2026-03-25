"""Sounding — network diagnostics MCP server.

Provides 14 tools for network probing, DNS, SSL inspection, speed testing,
and more.  Runs over stdio transport via FastMCP.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from typing import Optional

import dns.resolver
import dns.reversename
import httpx
from mcp.server.fastmcp import FastMCP

from sounding import __version__
from sounding.validators import (
    is_internal_ip,
    sanitize_domain,
    validate_host,
    validate_port,
    validate_subnet,
    validate_url,
)

mcp = FastMCP("sounding")

# Rate-limit state for port_scan.
_last_scan_time: float = 0.0
_scan_lock = asyncio.Lock()

# Default common ports for port_scan.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443,
]


# ---------------------------------------------------------------------------
# 1. health
# ---------------------------------------------------------------------------

@mcp.tool()
async def health() -> dict:
    """Return server version and status."""
    return {"status": "ok", "version": __version__}


# ---------------------------------------------------------------------------
# 2. ping
# ---------------------------------------------------------------------------

@mcp.tool()
async def ping(host: str, count: int = 4, timeout: int = 5) -> dict:
    """Ping a host using TCP connect (port 80) as a non-root ICMP alternative.

    Returns min/avg/max/jitter latency in milliseconds.
    """
    host = validate_host(host)
    if count < 1 or count > 100:
        raise ValueError("count must be between 1 and 100")

    latencies: list[float] = []
    errors: list[str] = []

    for _ in range(count):
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 80),
                timeout=timeout,
            )
            elapsed = (time.perf_counter() - start) * 1000  # ms
            latencies.append(elapsed)
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError) as exc:
            errors.append(str(exc))

    if not latencies:
        return {"host": host, "success": False, "errors": errors}

    avg = sum(latencies) / len(latencies)
    jitter = (
        (sum(abs(l - avg) for l in latencies) / len(latencies))
        if len(latencies) > 1
        else 0.0
    )

    return {
        "host": host,
        "success": True,
        "packets_sent": count,
        "packets_received": len(latencies),
        "packet_loss_pct": round((1 - len(latencies) / count) * 100, 1),
        "min_ms": round(min(latencies), 2),
        "avg_ms": round(avg, 2),
        "max_ms": round(max(latencies), 2),
        "jitter_ms": round(jitter, 2),
    }


# ---------------------------------------------------------------------------
# 3. traceroute
# ---------------------------------------------------------------------------

@mcp.tool()
async def traceroute(host: str, max_hops: int = 30) -> dict:
    """Trace the network route to a host.

    Wraps the system ``traceroute`` command and parses output.
    """
    host = validate_host(host)
    if max_hops < 1 or max_hops > 64:
        raise ValueError("max_hops must be between 1 and 64")

    try:
        proc = await asyncio.create_subprocess_exec(
            "traceroute", "-m", str(max_hops), "-w", "3", host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    except FileNotFoundError:
        return {"error": "traceroute command not found — install it on the host system"}
    except asyncio.TimeoutError:
        return {"error": "traceroute timed out"}

    lines = stdout.decode(errors="replace").strip().splitlines()
    hops: list[dict] = []
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 2:
            hops.append({"hop": parts[0], "detail": " ".join(parts[1:])})

    return {
        "host": host,
        "max_hops": max_hops,
        "hops": hops,
        "raw": stdout.decode(errors="replace"),
    }


# ---------------------------------------------------------------------------
# 4. dns_lookup
# ---------------------------------------------------------------------------

@mcp.tool()
async def dns_lookup(
    domain: str,
    record_type: str = "A",
    nameserver: Optional[str] = None,
) -> dict:
    """Resolve DNS records for a domain using dnspython.

    Supported record types: A, AAAA, MX, CNAME, TXT, NS.
    """
    domain = sanitize_domain(domain)
    record_type = record_type.upper()
    allowed_types = {"A", "AAAA", "MX", "CNAME", "TXT", "NS"}
    if record_type not in allowed_types:
        raise ValueError(f"record_type must be one of {allowed_types}")

    resolver = dns.resolver.Resolver()
    if nameserver:
        nameserver = validate_host(nameserver)
        resolver.nameservers = [nameserver]

    try:
        answers = await asyncio.get_event_loop().run_in_executor(
            None, lambda: resolver.resolve(domain, record_type)
        )
        records = [str(r) for r in answers]
    except dns.resolver.NXDOMAIN:
        return {"domain": domain, "record_type": record_type, "records": [], "error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        return {"domain": domain, "record_type": record_type, "records": [], "error": "No answer"}
    except dns.resolver.NoNameservers:
        return {"domain": domain, "record_type": record_type, "records": [], "error": "No nameservers"}
    except Exception as exc:
        return {"domain": domain, "record_type": record_type, "records": [], "error": str(exc)}

    return {"domain": domain, "record_type": record_type, "records": records}


# ---------------------------------------------------------------------------
# 5. reverse_dns
# ---------------------------------------------------------------------------

@mcp.tool()
async def reverse_dns(ip: str) -> dict:
    """Perform a reverse DNS lookup for an IP address."""
    ip = validate_host(ip)
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"reverse_dns requires an IP address, got: {ip!r}")

    try:
        rev_name = dns.reversename.from_address(ip)
        answers = await asyncio.get_event_loop().run_in_executor(
            None, lambda: dns.resolver.resolve(rev_name, "PTR")
        )
        hostnames = [str(r) for r in answers]
    except Exception as exc:
        return {"ip": ip, "hostnames": [], "error": str(exc)}

    return {"ip": ip, "hostnames": hostnames}


# ---------------------------------------------------------------------------
# 6. port_check
# ---------------------------------------------------------------------------

@mcp.tool()
async def port_check(host: str, port: int, timeout: int = 3) -> dict:
    """Check whether a single TCP port is open on a host."""
    host = validate_host(host)
    if not validate_port(port):
        raise ValueError(f"Invalid port: {port}")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return {"host": host, "port": port, "state": "open"}
    except (OSError, asyncio.TimeoutError):
        return {"host": host, "port": port, "state": "closed"}


# ---------------------------------------------------------------------------
# 7. port_scan
# ---------------------------------------------------------------------------

@mcp.tool()
async def port_scan(host: str, ports: Optional[list[int]] = None) -> dict:
    """Scan common TCP ports on a host.

    Safety limits: max 100 ports, rate-limited to one scan per second.
    """
    global _last_scan_time

    host = validate_host(host)
    if ports is None:
        ports = DEFAULT_PORTS
    if len(ports) > 100:
        raise ValueError("port_scan is limited to 100 ports per call")
    for p in ports:
        if not validate_port(p):
            raise ValueError(f"Invalid port in list: {p}")

    # Rate limiting — one scan per second.
    async with _scan_lock:
        now = time.monotonic()
        wait = 1.0 - (now - _last_scan_time)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_scan_time = time.monotonic()

    async def _check(p: int) -> dict:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, p),
                timeout=2,
            )
            writer.close()
            await writer.wait_closed()
            return {"port": p, "state": "open"}
        except (OSError, asyncio.TimeoutError):
            return {"port": p, "state": "closed"}

    results = await asyncio.gather(*[_check(p) for p in ports])
    open_ports = [r for r in results if r["state"] == "open"]

    return {
        "host": host,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "all_results": results,
    }


# ---------------------------------------------------------------------------
# 8. check_ssl_cert
# ---------------------------------------------------------------------------

@mcp.tool()
async def check_ssl_cert(host: str, port: int = 443) -> dict:
    """Inspect the SSL/TLS certificate on a host.

    Returns issuer, subject, expiry, SANs, and days until expiry.
    """
    host = validate_host(host)
    if not validate_port(port):
        raise ValueError(f"Invalid port: {port}")

    def _get_cert() -> dict:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
        # Re-parse with verification disabled to get the dict form.
        import ssl as _ssl
        pem = _ssl.DER_cert_to_PEM_cert(cert)
        # Use the stdlib to decode — connect again with getpeercert().
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock2:
            with ctx2.wrap_socket(sock2, server_hostname=host) as ssock2:
                return ssock2.getpeercert()

    try:
        cert_info = await asyncio.get_event_loop().run_in_executor(None, _get_cert)
    except Exception as exc:
        return {"host": host, "port": port, "error": str(exc)}

    if not cert_info:
        return {"host": host, "port": port, "error": "No certificate returned (peer unverified)"}

    # Parse expiry.
    not_after = cert_info.get("notAfter", "")
    try:
        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_until = (expiry_dt - datetime.now(timezone.utc)).days
    except (ValueError, TypeError):
        expiry_dt = None
        days_until = None

    # Extract SANs.
    sans = []
    for san_type, san_value in cert_info.get("subjectAltName", ()):
        sans.append(f"{san_type}:{san_value}")

    return {
        "host": host,
        "port": port,
        "subject": dict(x[0] for x in cert_info.get("subject", ())),
        "issuer": dict(x[0] for x in cert_info.get("issuer", ())),
        "not_before": cert_info.get("notBefore"),
        "not_after": not_after,
        "days_until_expiry": days_until,
        "sans": sans,
        "serial": cert_info.get("serialNumber"),
    }


# ---------------------------------------------------------------------------
# 9. whois_lookup
# ---------------------------------------------------------------------------

@mcp.tool()
async def whois_lookup(domain: str) -> dict:
    """WHOIS lookup for a domain using the system ``whois`` command."""
    domain = sanitize_domain(domain)

    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
    except FileNotFoundError:
        return {"error": "whois command not found — install it on the host system"}
    except asyncio.TimeoutError:
        return {"error": "whois lookup timed out"}

    output = stdout.decode(errors="replace")

    # Parse common fields.
    info: dict[str, str | None] = {
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiry_date": None,
        "name_servers": [],
    }

    for line in output.splitlines():
        lower = line.lower().strip()
        if lower.startswith("registrar:"):
            info["registrar"] = line.split(":", 1)[1].strip()
        elif lower.startswith("creation date:"):
            info["creation_date"] = line.split(":", 1)[1].strip()
        elif "expir" in lower and "date" in lower and ":" in line:
            info["expiry_date"] = line.split(":", 1)[1].strip()
        elif lower.startswith("name server:"):
            ns = line.split(":", 1)[1].strip()
            if ns:
                info["name_servers"].append(ns)

    info["raw"] = output
    return info


# ---------------------------------------------------------------------------
# 10. http_check
# ---------------------------------------------------------------------------

@mcp.tool()
async def http_check(url: str) -> dict:
    """Perform an HTTP request and return timing breakdown.

    Returns status code, timing (DNS, connect, TLS, TTFB, total),
    response size, and headers.
    """
    url = validate_url(url)

    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(30.0),
            verify=False,  # Allow self-signed certs for diagnostics.
        ) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return {"url": url, "error": str(exc), "total_ms": round(elapsed, 2)}

    total_ms = (time.perf_counter() - start) * 1000

    return {
        "url": url,
        "status_code": response.status_code,
        "total_ms": round(total_ms, 2),
        "response_size_bytes": len(response.content),
        "headers": dict(response.headers),
    }


# ---------------------------------------------------------------------------
# 11. subnet_scan
# ---------------------------------------------------------------------------

@mcp.tool()
async def subnet_scan(subnet: str) -> dict:
    """Discover live hosts on a local subnet by probing common ports.

    Only allows RFC 1918 private subnets for safety.
    Probes TCP ports 22, 80, and 443 on each host.
    """
    subnet = validate_subnet(subnet)
    network = ipaddress.IPv4Network(subnet, strict=False)

    # Safety: cap at /20 (4096 hosts).
    if network.num_addresses > 4096:
        raise ValueError("Subnet too large — maximum /20 (4096 addresses)")

    probe_ports = [22, 80, 443]

    async def _probe(ip: str) -> dict | None:
        for port in probe_ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=1,
                )
                writer.close()
                await writer.wait_closed()
                return {"ip": ip, "open_port": port}
            except (OSError, asyncio.TimeoutError):
                continue
        return None

    # Run probes with concurrency limit.
    sem = asyncio.Semaphore(50)

    async def _limited_probe(ip: str) -> dict | None:
        async with sem:
            return await _probe(ip)

    hosts = [str(ip) for ip in network.hosts()]
    results = await asyncio.gather(*[_limited_probe(h) for h in hosts])
    found = [r for r in results if r is not None]

    return {
        "subnet": subnet,
        "hosts_scanned": len(hosts),
        "hosts_found": len(found),
        "hosts": found,
    }


# ---------------------------------------------------------------------------
# 12. get_public_ip
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_public_ip() -> dict:
    """Get the public IP address of this machine."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get("https://httpbin.org/ip")
            data = response.json()
            return {"public_ip": data.get("origin", "unknown")}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# 13. speed_test
# ---------------------------------------------------------------------------

# Cloudflare speed test endpoints — downloads a known payload and times it.
_SPEED_TEST_URLS = [
    # 10 MB payload from Cloudflare
    ("Cloudflare", "https://speed.cloudflare.com/__down?bytes=10000000"),
]


@mcp.tool()
async def speed_test() -> dict:
    """Measure network download speed and latency.

    Downloads a 10 MB test payload from Cloudflare and measures throughput.
    Also measures latency with multiple TCP connect pings.
    Returns download speed in Mbps and latency stats in milliseconds.
    """
    # ── Latency measurement (5 TCP pings to Cloudflare) ──
    latencies: list[float] = []
    for _ in range(5):
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("speed.cloudflare.com", 443),
                timeout=5,
            )
            elapsed = (time.perf_counter() - start) * 1000
            latencies.append(elapsed)
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            pass

    latency_stats: dict = {}
    if latencies:
        avg = sum(latencies) / len(latencies)
        latency_stats = {
            "min_ms": round(min(latencies), 2),
            "avg_ms": round(avg, 2),
            "max_ms": round(max(latencies), 2),
        }

    # ── Download speed measurement ──
    test_server, test_url = _SPEED_TEST_URLS[0]
    download_mbps: float | None = None
    download_bytes: int = 0
    download_ms: float = 0.0
    dl_error: str | None = None

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(60.0),
            follow_redirects=True,
        ) as client:
            start = time.perf_counter()
            response = await client.get(test_url)
            download_ms = (time.perf_counter() - start) * 1000
            download_bytes = len(response.content)

            if download_bytes > 0 and download_ms > 0:
                # bits / milliseconds → megabits per second
                download_mbps = round(
                    (download_bytes * 8) / (download_ms / 1000) / 1_000_000, 2
                )
    except Exception as exc:
        dl_error = str(exc)

    result: dict = {
        "test_server": test_server,
        "latency": latency_stats if latency_stats else {"error": "All pings failed"},
    }

    if dl_error:
        result["download"] = {"error": dl_error}
    else:
        result["download"] = {
            "speed_mbps": download_mbps,
            "bytes_transferred": download_bytes,
            "duration_ms": round(download_ms, 2),
        }

    return result


# ---------------------------------------------------------------------------
# 14. dns_propagation
# ---------------------------------------------------------------------------

# Public DNS resolvers for propagation checks.
_PUBLIC_RESOLVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "OpenDNS": "208.67.222.222",
    "Quad9": "9.9.9.9",
}


@mcp.tool()
async def dns_propagation(
    domain: str,
    record_type: str = "A",
) -> dict:
    """Check DNS propagation across multiple public resolvers.

    Queries Google (8.8.8.8), Cloudflare (1.1.1.1), OpenDNS (208.67.222.222),
    Quad9 (9.9.9.9), and the system default resolver in parallel, then
    highlights any inconsistencies between them.

    Supported record types: A, AAAA, CNAME, MX, TXT.
    """
    domain = sanitize_domain(domain)
    record_type = record_type.upper()
    allowed_types = {"A", "AAAA", "CNAME", "MX", "TXT"}
    if record_type not in allowed_types:
        raise ValueError(f"record_type must be one of {allowed_types}")

    async def _query(name: str, nameserver: str | None) -> dict:
        """Query a single resolver and return its results."""
        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.lifetime = 10  # seconds

        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None, lambda: resolver.resolve(domain, record_type)
            )
            records = sorted(str(r) for r in answers)
            ttl = answers.rrset.ttl if answers.rrset else None
            return {"resolver": name, "nameserver": nameserver or "system", "records": records, "ttl": ttl}
        except dns.resolver.NXDOMAIN:
            return {"resolver": name, "nameserver": nameserver or "system", "records": [], "error": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            return {"resolver": name, "nameserver": nameserver or "system", "records": [], "error": "No answer"}
        except dns.resolver.NoNameservers:
            return {"resolver": name, "nameserver": nameserver or "system", "records": [], "error": "No nameservers"}
        except Exception as exc:
            return {"resolver": name, "nameserver": nameserver or "system", "records": [], "error": str(exc)}

    # Build tasks: named resolvers + system default
    tasks = [_query(name, ns) for name, ns in _PUBLIC_RESOLVERS.items()]
    tasks.append(_query("System Default", None))

    results = await asyncio.gather(*tasks)

    # Detect inconsistencies — compare record sets across resolvers
    record_sets: dict[str, set[str]] = {}
    for r in results:
        if "error" not in r:
            record_sets[r["resolver"]] = set(r["records"])

    consistent = True
    if len(record_sets) > 1:
        reference = next(iter(record_sets.values()))
        for rs in record_sets.values():
            if rs != reference:
                consistent = False
                break

    return {
        "domain": domain,
        "record_type": record_type,
        "consistent": consistent,
        "resolvers": results,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run the Sounding MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
