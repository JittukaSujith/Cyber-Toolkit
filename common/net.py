"""Small networking primitives shared by the scanners."""
from __future__ import annotations

import socket

# A short, well-known service table. Used when the OS services database has no entry.
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog",
    554: "rtsp", 587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1883: "mqtt", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8008: "http-alt", 8009: "chromecast", 8080: "http-proxy", 8443: "https-alt",
    9100: "jetdirect", 27017: "mongodb", 62078: "iphone-sync",
}

# Services that are risky when exposed (cleartext or frequently misconfigured).
RISKY_PORTS = {
    21: "FTP sends credentials in cleartext",
    23: "Telnet sends everything in cleartext - use SSH",
    135: "MSRPC exposed",
    139: "NetBIOS exposed",
    445: "SMB exposed (common ransomware entry point)",
    3389: "RDP exposed (frequent brute-force target)",
    5900: "VNC exposed (often weak/no authentication)",
    6379: "Redis often runs without authentication",
    27017: "MongoDB often runs without authentication",
}


def service_name(port: int) -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Return True if a full TCP handshake succeeds.

    SECURITY IDEA: A "connect scan" completes the three-way handshake (SYN, SYN-ACK,
    ACK). If it succeeds, something is listening. It is noisy (it shows in server
    logs) but needs no special privileges, unlike a half-open SYN scan.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def grab_banner(host: str, port: int, timeout: float = 1.5) -> str:
    """Read the first bytes a service volunteers (many send a greeting banner)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in (80, 8000, 8008, 8080):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(256)
            return data.decode("utf-8", errors="replace").strip().splitlines()[0][:100] if data.strip() else ""
    except (OSError, IndexError):
        return ""


def resolve_host(host: str) -> str:
    """Resolve a hostname to an IPv4 address (raises ValueError on failure)."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError(f"could not resolve '{host}'")
