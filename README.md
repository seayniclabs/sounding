# Sounding

**Network Diagnostics MCP Server**

[![License: MIT](https://img.shields.io/badge/License-MIT-818CF8.svg)](LICENSE)

*Probing what lies beneath the surface -- network diagnostics for AI tools.*

---

## What It Does

Sounding is a [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server that gives AI assistants 14 network diagnostic tools. It handles the things you'd normally reach for `ping`, `dig`, `nmap`, or `openssl` to do -- but exposed as structured, validated MCP tool calls.

## Tools

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `health` | Server version and status check | -- |
| `ping` | TCP connect ping (port 80) with latency stats | `host`, `count` (1--100), `timeout` |
| `traceroute` | Trace network route to a host | `host`, `max_hops` (1--64) |
| `dns_lookup` | Resolve DNS records (A, AAAA, MX, CNAME, TXT, NS) | `domain`, `record_type`, `nameserver` |
| `reverse_dns` | Reverse DNS lookup for an IP address | `ip` |
| `port_check` | Check if a single TCP port is open | `host`, `port`, `timeout` |
| `port_scan` | Scan common TCP ports (rate-limited, max 100) | `host`, `ports` |
| `check_ssl_cert` | Inspect SSL/TLS certificate details and expiry | `host`, `port` |
| `whois_lookup` | WHOIS domain registration lookup | `domain` |
| `http_check` | HTTP request with status, timing, headers, size | `url` |
| `subnet_scan` | Discover live hosts on a local subnet (RFC 1918 only) | `subnet` (CIDR, max /20) |
| `get_public_ip` | Get the machine's public IP address | -- |
| `speed_test` | Measure download speed (Mbps) and latency | -- |
| `dns_propagation` | Check DNS propagation across public resolvers | `domain`, `record_type` |

## Installation

From PyPI:

```bash
pip install sounding-mcp
```

Or isolated with pipx:

```bash
pipx install sounding-mcp
```

## Usage

Run the server directly (stdio transport):

```bash
sounding
```

### Claude Code

Register as a local MCP server:

```bash
claude mcp add sounding -- sounding
```

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sounding": {
      "command": "sounding",
      "args": []
    }
  }
}
```

If installed in a virtual environment, use the full path to the binary:

```json
{
  "mcpServers": {
    "sounding": {
      "command": "/path/to/.venv/bin/sounding",
      "args": []
    }
  }
}
```

## Security

Sounding is designed to be safe for AI-driven use:

- **SSRF protection** -- `http_check` resolves hostnames and blocks requests to internal, private, loopback, and link-local IP addresses (including IPv4-mapped IPv6). Cloud metadata endpoints (169.254.x.x) are blocked.
- **Input validation** -- All inputs pass through validators that reject shell metacharacters, malformed hostnames, and invalid ports before reaching any network call or subprocess.
- **Rate limiting** -- `port_scan` enforces a minimum 1-second interval between scans to prevent abuse.
- **Subnet restriction** -- `subnet_scan` only allows RFC 1918 private subnets and caps at /20 (4096 addresses) with concurrency limiting.
- **No shell injection** -- Subprocess calls (`traceroute`, `whois`) use `exec`-style invocation, never shell interpolation.

## Development

```bash
git clone https://github.com/seayniclabs/sounding.git
cd sounding
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
python -m pytest tests/ -q
```

## License

[MIT](LICENSE)
