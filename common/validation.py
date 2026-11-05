"""
Input validation helpers.

SECURITY IDEA: Never trust input. Even in a learning tool, validating user input
(hostnames, ports, URLs) prevents crashes, accidental scans of the wrong target,
and, in real applications, injection bugs. Validate early, fail with a clear message.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^(?:{_LABEL}\.)*{_LABEL}$")


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    return bool(value) and len(value) <= 253 and bool(_HOSTNAME_RE.match(value))


def validate_host(value: str) -> str:
    """Return a cleaned hostname/IP or raise ValueError."""
    value = (value or "").strip().lower()
    if is_valid_ip(value) or is_valid_hostname(value):
        return value
    raise ValueError(f"'{value}' is not a valid hostname or IP address")


def validate_domain(value: str) -> str:
    """A domain must be a hostname with at least one dot (not an IP)."""
    value = validate_host(value)
    if is_valid_ip(value) or "." not in value:
        raise ValueError(f"'{value}' is not a valid domain name (example: example.com)")
    return value


def validate_port(value) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"'{value}' is not a valid port number")
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} is out of range (1-65535)")
    return port


def parse_port_spec(spec: str) -> list[int]:
    """Parse '22,80,8000-8100' into a sorted, de-duplicated list of ports."""
    ports: set[int] = set()
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            lo_i, hi_i = validate_port(lo), validate_port(hi)
            if lo_i > hi_i:
                raise ValueError(f"invalid range '{part}' (start is greater than end)")
            ports.update(range(lo_i, hi_i + 1))
        else:
            ports.add(validate_port(part))
    if not ports:
        raise ValueError("no ports specified")
    return sorted(ports)


def normalize_url(value: str, default_scheme: str = "https") -> str:
    """Add a scheme if missing and make sure the URL is http(s) with a valid host."""
    value = (value or "").strip()
    if not value:
        raise ValueError("URL is empty")
    if "://" not in value:
        value = f"{default_scheme}://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme '{parsed.scheme}' (use http or https)")
    if not parsed.hostname:
        raise ValueError("URL has no hostname")
    validate_host(parsed.hostname)
    return value
