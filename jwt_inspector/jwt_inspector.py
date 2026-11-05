#!/usr/bin/env python3
"""
JWT Inspector (CLI): decode a JSON Web Token and flag risky settings.

SECURITY IDEAS:
  * A JWT is  base64url(header) . base64url(payload) . signature.  Base64 is ENCODING,
    not encryption: anyone can read the payload, so never put secrets in it.
  * Decoding is not verifying. Only a valid signature proves the token is genuine.
  * Classic JWT mistakes:
      - alg "none": server accepts unsigned tokens
      - algorithm confusion: server trusts the token's own 'alg' header (e.g. RS256 -> HS256)
      - weak HMAC secrets that can be guessed offline
      - no 'exp' (token never expires) or very long lifetimes
      - 'kid' / 'jku' / 'x5u' headers that make the server fetch or look up attacker-chosen keys
This tool inspects tokens you already have; it does not forge them.
Use --demo to generate a sample token (signed with a weak secret) to practise on.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import hmac
import json
import sys

HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
TINY_WEAK_LIST = ["secret", "password", "changeme", "123456", "admin", "jwtsecret"]  # illustrative only
TIME_CLAIMS = ("exp", "iat", "nbf")


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_token(token: str) -> tuple[dict, dict, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("a JWT has exactly 3 dot-separated parts (header.payload.signature)")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, binascii.Error):  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        raise ValueError("header/payload are not valid base64url-encoded JSON")
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("header and payload must be JSON objects")
    return header, payload, parts[2]


def verify_hmac(token: str, secret: str) -> bool:
    header, _, signature = decode_token(token)
    alg = header.get("alg")
    if alg not in HMAC_ALGS:
        raise ValueError(f"cannot verify alg '{alg}' (only HS256/384/512 supported)")
    signing_input = token.strip().rsplit(".", 1)[0].encode()
    expected = b64url_encode(hmac.new(secret.encode(), signing_input, HMAC_ALGS[alg]).digest())
    return hmac.compare_digest(expected, signature)  # constant-time compare


def analyze(header: dict, payload: dict, signature: str, now: dt.datetime | None = None) -> list[tuple[str, str]]:
    now = now or dt.datetime.now(dt.timezone.utc)
    issues = []
    alg = str(header.get("alg", "")).upper()
    if alg == "NONE" or not signature:
        issues.append(("HIGH", "alg is 'none' / no signature: token is unsigned and trivially forgeable"))
    elif alg in HMAC_ALGS:
        issues.append(("INFO", f"{alg} is symmetric: the same secret signs and verifies, so it must be long and random"))
    if "exp" not in payload:
        issues.append(("MEDIUM", "No 'exp' claim: token never expires"))
    else:
        try:
            exp = dt.datetime.fromtimestamp(float(payload["exp"]), dt.timezone.utc)
            if exp < now:
                issues.append(("INFO", f"Token EXPIRED at {exp:%Y-%m-%d %H:%M UTC}"))
            if "iat" in payload and float(payload["exp"]) - float(payload["iat"]) > 30 * 24 * 3600:
                issues.append(("MEDIUM", "Lifetime longer than 30 days for a bearer token"))
        except (TypeError, ValueError, OverflowError, OSError):
            issues.append(("MEDIUM", "'exp' is not a valid timestamp"))
    for claim in ("iss", "aud"):
        if claim not in payload:
            issues.append(("LOW", f"No '{claim}' claim: receivers cannot check who issued it / who it is for"))
    for h in ("kid", "jku", "x5u", "jwk"):
        if h in header:
            issues.append(("MEDIUM", f"Header '{h}' present: servers must strictly validate it (key-injection / SSRF / path-traversal risk)"))
    if any(k in payload for k in ("password", "pwd", "secret", "ssn", "credit_card")):
        issues.append(("HIGH", "Payload contains sensitive-looking data; JWT payloads are readable by anyone"))
    return issues


def check_weak_secrets(token: str) -> str | None:
    """Return the matching secret if the token was signed with one of a few famous weak secrets."""
    for secret in TINY_WEAK_LIST:
        try:
            if verify_hmac(token, secret):
                return secret
        except ValueError:
            return None  # not an HMAC token
    return None


def make_demo_token() -> str:
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url_encode(json.dumps({"sub": "1234", "name": "Demo User", "role": "user", "iat": now}).encode())
    sig = b64url_encode(hmac.new(b"secret", f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def fmt_time_claims(payload: dict) -> dict:
    out = {}
    for c in TIME_CLAIMS:
        if c in payload:
            try:
                out[c] = f"{dt.datetime.fromtimestamp(float(payload[c]), dt.timezone.utc):%Y-%m-%d %H:%M:%S UTC}"
            except (TypeError, ValueError, OverflowError, OSError):
                out[c] = "invalid"
    return out


def main() -> None:
    p = argparse.ArgumentParser(description="Decode and audit a JWT (decoding is NOT verification).")
    p.add_argument("token", nargs="?", help="the JWT (or use --demo)")
    p.add_argument("--secret", help="verify an HS256/384/512 signature with this secret")
    p.add_argument("--check-weak-secrets", action="store_true", help="test a tiny list of well-known weak HMAC secrets")
    p.add_argument("--demo", action="store_true", help="generate and inspect a sample token")
    args = p.parse_args()

    token = make_demo_token() if args.demo else args.token
    if not token:
        p.error("provide a token or --demo")
    try:
        header, payload, sig = decode_token(token)
        if args.demo:
            print("DEMO TOKEN:", token, "\n")
        print("HEADER :", json.dumps(header, indent=2))
        print("PAYLOAD:", json.dumps(payload, indent=2))
        for claim, text in fmt_time_claims(payload).items():
            print(f"  {claim} = {text}")
        print("\nFindings:")
        for sev, msg in analyze(header, payload, sig) or [("OK", "No obvious issues")]:
            print(f"  [{sev}] {msg}")
        if args.secret is not None:
            print("\nSignature:", "VALID for the supplied secret" if verify_hmac(token, args.secret) else "INVALID for the supplied secret")
        if args.check_weak_secrets:
            weak = check_weak_secrets(token)
            print("\nWeak-secret check:", f"[HIGH] signed with well-known secret '{weak}'" if weak else "none of the tiny list matched")
    except ValueError as exc:
        sys.exit(f"Error: {exc}")


if __name__ == "__main__":
    main()
