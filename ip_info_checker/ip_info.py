#!/usr/bin/env python3
"""
IP Info Checker (CLI)

SECURITY IDEA: Triage starts with "what is this address?". Is it private (RFC 1918),
loopback, link-local, or public? Who owns it (ASN/organisation)? What does reverse
DNS say? Analysts ask these questions when reading firewall logs or alerts.
Local classification uses Python's `ipaddress` module (offline). Public addresses
can optionally be enriched via the free ipinfo.io API (rate limited, no key needed).
Never paste sensitive internal data into third-party lookup services.
"""
from __future__ import annotations

import argparse
import ipaddress
import pathlib
import socket
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from common.validation import is_valid_ip, validate_host  # noqa: E402


def classify(ip_text: str) -> dict:
    ip = ipaddress.ip_address(ip_text)
    if ip.is_loopback: kind = "Loopback (this machine only)"
    elif ip.is_link_local: kind = "Link-local (auto-assigned, not routable)"
    elif ip.is_private: kind = "Private (internal network / RFC 1918 or ULA)"
    elif ip.is_multicast: kind = "Multicast"
    elif ip.is_reserved or ip.is_unspecified: kind = "Reserved / unspecified"
    else: kind = "Public (routable on the internet)"
    return {"version": f"IPv{ip.version}", "type": kind, "is_global": ip.is_global,
            "reverse_pointer": ip.reverse_pointer}


def reverse_dns(ip_text: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip_text)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def online_lookup(ip_text: str) -> dict:
    import requests
    resp = requests.get(f"https://ipinfo.io/{ip_text}/json", timeout=8)
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="Classify and look up an IP address or hostname.")
    parser.add_argument("target", help="IP address or hostname")
    parser.add_argument("--offline", action="store_true", help="skip the online geolocation/ASN lookup")
    args = parser.parse_args()

    try:
        target = validate_host(args.target)
        ip_text = target if is_valid_ip(target) else socket.gethostbyname(target)
    except ValueError as exc:
        sys.exit(f"Error: {exc}")
    except socket.gaierror:
        sys.exit(f"Error: could not resolve '{args.target}'")

    info = classify(ip_text)
    print(f"Target       : {args.target}" + (f" -> {ip_text}" if ip_text != target else ""))
    print(f"Version      : {info['version']}")
    print(f"Type         : {info['type']}")
    print(f"Reverse DNS  : {reverse_dns(ip_text) or 'none'}")

    if args.offline or not info["is_global"]:
        print("Online lookup: skipped" + (" (non-public address)" if not info["is_global"] else ""))
        return
    try:
        data = online_lookup(ip_text)
        for label, key in (("Org / ASN", "org"), ("City", "city"), ("Region", "region"), ("Country", "country"), ("Timezone", "timezone")):
            print(f"{label:<13}: {data.get(key, 'n/a')}")
        print("Note         : geolocation is approximate and often wrong below country level.")
    except Exception as exc:
        print(f"Online lookup failed: {exc}")


if __name__ == "__main__":
    main()
