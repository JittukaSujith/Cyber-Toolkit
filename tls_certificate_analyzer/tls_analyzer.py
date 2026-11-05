#!/usr/bin/env python3
"""
TLS Certificate Analyzer (CLI)

SECURITY IDEA: A TLS certificate binds a public key to a domain name, vouched for
by a Certificate Authority (CA). Things that go wrong in practice:
  * expired or soon-to-expire certificates (outages / users trained to click through)
  * hostname mismatch (certificate was issued for a different site)
  * self-signed or untrusted chain (anyone can mint one; no third-party vouching)
  * weak keys (RSA < 2048) or weak signature hashes (MD5/SHA-1 are collision-prone)
  * old protocol versions (TLS 1.0/1.1 are deprecated)
We make two connections: one that VERIFIES the certificate the way a browser would,
and one that merely downloads it so we can inspect it even when it is broken.

Requires: cryptography (pip install cryptography)
"""
from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import socket
import ssl
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from common.validation import validate_host, validate_port  # noqa: E402


def fetch_certificate_der(host: str, port: int, timeout: float) -> bytes:
    """Download the leaf certificate WITHOUT validating it (so we can inspect bad ones)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inspection only, never use this to trust a site
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True)


def verified_handshake(host: str, port: int, timeout: float) -> dict:
    """Do a normal, validating handshake and report protocol, cipher and trust result."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return {"trusted": True, "error": None, "version": tls.version(), "cipher": tls.cipher()}
    except ssl.SSLCertVerificationError as exc:
        return {"trusted": False, "error": exc.verify_message, "version": None, "cipher": None}


def hostname_matches(host: str, names: list[str]) -> bool:
    """Match a hostname against SAN entries, supporting a single leading wildcard."""
    host = host.lower()
    for name in (n.lower() for n in names):
        if name == host:
            return True
        if name.startswith("*.") and host.count(".") == name.count(".") and host.endswith(name[1:]):
            return True
    return False


def analyze(der: bytes, host: str) -> dict:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    cert = x509.load_der_x509_certificate(der)
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc, key_bits = f"RSA {key.key_size}", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc, key_bits = f"EC {key.curve.name}", key.key_size
    else:
        key_desc, key_bits = type(key).__name__, 0
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"

    now = dt.datetime.now(dt.timezone.utc)
    days_left = (not_after - now).days
    issues: list[tuple[str, str]] = []
    if now > not_after:
        issues.append(("HIGH", f"Certificate EXPIRED {-days_left} days ago"))
    elif now < not_before:
        issues.append(("HIGH", "Certificate is not yet valid"))
    elif days_left < 14:
        issues.append(("MEDIUM", f"Expires in {days_left} days"))
    if not hostname_matches(host, sans or [cert.subject.rfc4514_string()]):
        issues.append(("HIGH", f"Hostname '{host}' does not match certificate names"))
    if cert.issuer == cert.subject:
        issues.append(("HIGH", "Self-signed certificate (no CA vouching for it)"))
    if sig in ("md5", "sha1"):
        issues.append(("HIGH", f"Weak signature hash: {sig}"))
    if isinstance(key, rsa.RSAPublicKey) and key_bits < 2048:
        issues.append(("HIGH", f"Weak RSA key size: {key_bits} bits"))

    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "not_before": not_before, "not_after": not_after, "days_left": days_left,
            "sans": sans, "key": key_desc, "signature": sig, "serial": format(cert.serial_number, "x"),
            "issues": issues}


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze a server's TLS certificate.")
    parser.add_argument("host", help="hostname, e.g. example.com")
    parser.add_argument("-p", "--port", default=443, type=int)
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()

    try:
        host, port = validate_host(args.host), validate_port(args.port)
        der = fetch_certificate_der(host, port, args.timeout)
        info = analyze(der, host)
        handshake = verified_handshake(host, port, args.timeout)
    except ValueError as exc:
        sys.exit(f"Error: {exc}")
    except (OSError, ssl.SSLError) as exc:
        sys.exit(f"Connection/TLS failure: {exc}")

    print(f"TLS analysis for {host}:{port}\n{'=' * 50}")
    print(f"Subject    : {info['subject']}")
    print(f"Issuer     : {info['issuer']}")
    print(f"Valid      : {info['not_before']:%Y-%m-%d} -> {info['not_after']:%Y-%m-%d}  ({info['days_left']} days left)")
    print(f"Key / Sig  : {info['key']} / {info['signature']}")
    print(f"Names (SAN): {', '.join(info['sans'][:8])}{' ...' if len(info['sans']) > 8 else ''}")
    print(f"Serial     : {info['serial']}")
    if handshake["trusted"]:
        print(f"Trust      : TRUSTED by this system's CA store | {handshake['version']} | {handshake['cipher'][0]}")
        if handshake["version"] in ("TLSv1", "TLSv1.1"):
            info["issues"].append(("HIGH", f"Deprecated protocol negotiated: {handshake['version']}"))
    else:
        print(f"Trust      : NOT TRUSTED -> {handshake['error']}")
    print("\nFindings:")
    for sev, msg in info["issues"] or [("OK", "No problems found")]:
        print(f"  [{sev}] {msg}")


if __name__ == "__main__":
    main()
