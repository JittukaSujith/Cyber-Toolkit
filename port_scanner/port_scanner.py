#!/usr/bin/env python3
"""
TCP Port Scanner (CLI)

SECURITY IDEA: Every open port is a door into a machine. Attackers enumerate open
ports to find services to attack; defenders run the same scan against their OWN
systems to spot unexpected exposure (an forgotten database, a Telnet server).
This is a TCP "connect" scan: slow-ish and noisy but dependable and needs no root.
Threads let us probe many ports concurrently since most time is spent waiting.

ONLY scan hosts you own or have written permission to test.
"""
from __future__ import annotations

import argparse
import pathlib
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from common.consent import add_permission_flag, require_authorization  # noqa: E402
from common.net import RISKY_PORTS, COMMON_SERVICES, grab_banner, resolve_host, service_name, tcp_connect  # noqa: E402
from common.validation import parse_port_spec, validate_host  # noqa: E402

TOP_PORTS = sorted(COMMON_SERVICES)  # a small curated "top ports" list


def scan(host: str, ports: list[int], timeout: float, workers: int) -> list[int]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: (p, tcp_connect(host, p, timeout)), ports)
        return sorted(p for p, is_open in results if is_open)


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple threaded TCP connect port scanner.")
    parser.add_argument("host", help="target hostname or IP (must be yours to test)")
    parser.add_argument("-p", "--ports", default="top", help="'top', '1-1024', or '22,80,443' (default: top)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="seconds per connection attempt")
    parser.add_argument("-w", "--workers", type=int, default=100, help="concurrent threads (max 500)")
    parser.add_argument("-b", "--banner", action="store_true", help="try to grab service banners on open ports")
    add_permission_flag(parser)
    args = parser.parse_args()

    try:
        host = validate_host(args.host)
        ports = TOP_PORTS if args.ports == "top" else parse_port_spec(args.ports)
        if not 0 < args.timeout <= 10:
            raise ValueError("timeout must be between 0 and 10 seconds")
        workers = max(1, min(args.workers, 500))
        ip = resolve_host(host)
    except ValueError as exc:
        sys.exit(f"Error: {exc}")

    require_authorization(host, args.i_have_permission)
    print(f"Scanning {host} ({ip}) - {len(ports)} port(s)...")
    start = time.time()
    open_ports = scan(ip, ports, args.timeout, workers)
    print(f"\n{'PORT':<8}{'SERVICE':<14}NOTES")
    for port in open_ports:
        notes = RISKY_PORTS.get(port, "")
        if args.banner:
            banner = grab_banner(ip, port)
            notes = f"{notes} | banner: {banner}".strip(" |") if banner else notes
        print(f"{port:<8}{service_name(port):<14}{notes}")
    print(f"\n{len(open_ports)} open / {len(ports)} scanned in {time.time() - start:.1f}s")
    print("Closed and filtered ports look the same to a connect scan (filtered = firewall silently drops).")


if __name__ == "__main__":
    main()
