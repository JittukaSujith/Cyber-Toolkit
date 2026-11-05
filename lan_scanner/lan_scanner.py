#!/usr/bin/env python3
"""
LAN Scanner (CLI): discover live hosts on your local network.

SECURITY IDEA: You cannot defend what you do not know exists. Asset discovery is the
first step of network security: find forgotten printers, cameras, or rogue devices.
ICMP ping needs raw sockets (admin rights), so this tool uses two unprivileged tricks:
  1. Try TCP connections to a few common ports; any reply (even a "refused") proves
     the host is alive.
  2. Read the OS ARP cache, which lists MAC addresses of machines we just talked to
     (works only on the local subnet - ARP is a layer-2 protocol).

ONLY scan networks you own or administer.
"""
from __future__ import annotations

import argparse
import ipaddress
import pathlib
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from common.consent import add_permission_flag, require_authorization  # noqa: E402

PROBE_PORTS = (80, 443, 22, 445, 139, 135, 53, 8080, 62078)
MAX_HOSTS = 1024  # safety limit: nothing bigger than a /22


def local_cidr() -> str:
    """Guess our own /24 by asking the OS which interface routes to the internet (no packets sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))  # TEST-NET address; UDP connect() just picks a route
            ip = s.getsockname()[0]
        except OSError:
            sys.exit("Could not detect local network. Pass --cidr 192.168.1.0/24")
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def parse_cidr(text: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f"'{text}' is not a valid CIDR range (example: 192.168.1.0/24)")
    if net.version != 4:
        raise ValueError("only IPv4 is supported")
    if not net.is_private:
        raise ValueError("refusing to scan a non-private range with this tool")
    if net.num_addresses > MAX_HOSTS:
        raise ValueError(f"range too large (max {MAX_HOSTS} addresses, i.e. /22)")
    return net


def probe(ip: str, timeout: float) -> bool:
    for port in PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return True  # a refusal means a live host answered with RST
        except OSError:
            continue
    return False


def read_arp_table() -> dict[str, str]:
    """Parse `arp -a` output (Windows/macOS/Linux formats) into {ip: mac}."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    table = {}
    for ip, mac in re.findall(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", out):
        table[ip] = mac.lower().replace("-", ":")
    return table


def hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover live hosts on a private network.")
    parser.add_argument("--cidr", help="range to scan (default: your local /24)")
    parser.add_argument("--timeout", type=float, default=0.4)
    add_permission_flag(parser)
    args = parser.parse_args()

    try:
        net = parse_cidr(args.cidr or local_cidr())
    except ValueError as exc:
        sys.exit(f"Error: {exc}")
    if not 0 < args.timeout <= 5:
        sys.exit("Error: timeout must be between 0 and 5 seconds")

    require_authorization(str(net), args.i_have_permission)
    hosts = [str(h) for h in net.hosts()]
    print(f"Scanning {len(hosts)} addresses in {net} ...")
    with ThreadPoolExecutor(max_workers=128) as pool:
        alive = {ip for ip, up in zip(hosts, pool.map(lambda h: probe(h, args.timeout), hosts)) if up}

    arp = read_arp_table()
    alive |= {ip for ip in arp if ipaddress.ip_address(ip) in net and not ipaddress.ip_address(ip).is_multicast
              and not ip.endswith(".255")}  # ARP may reveal hosts that ignore our probes
    print(f"\n{'IP':<16}{'MAC':<20}HOSTNAME")
    for ip in sorted(alive, key=ipaddress.ip_address):
        print(f"{ip:<16}{arp.get(ip, 'unknown'):<20}{hostname(ip)}")
    print(f"\n{len(alive)} device(s) found. Review the list: do you recognise every device?")


if __name__ == "__main__":
    main()
