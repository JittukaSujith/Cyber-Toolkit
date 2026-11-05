#!/usr/bin/env python3
"""
Cookie Security Audit (CLI)

SECURITY IDEA: Session cookies are bearer tokens: whoever holds one IS the user.
Cookie attributes defend them:
  * Secure   - only sent over HTTPS (blocks sniffing on open Wi-Fi)
  * HttpOnly - invisible to JavaScript (limits theft via XSS)
  * SameSite - restricts cross-site sending (mitigates CSRF); Lax or Strict
  * __Host- / __Secure- prefixes - browser-enforced guarantees
  * Short lifetime / narrow Domain+Path - smaller window and blast radius
"""
from __future__ import annotations

import argparse
import pathlib
import sys
from http.cookies import CookieError, SimpleCookie

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from common.validation import normalize_url  # noqa: E402

SESSION_HINTS = ("sess", "sid", "token", "auth", "jwt", "login", "csrf", "remember")


def audit_set_cookie(header: str, is_https: bool) -> dict:
    """Audit one raw Set-Cookie header. Pure function, easy to unit test."""
    jar = SimpleCookie()
    try:
        jar.load(header)
    except CookieError as exc:
        return {"name": "?", "issues": [("HIGH", f"Malformed cookie: {exc}")]}
    if not jar:
        return {"name": "?", "issues": [("MEDIUM", "Could not parse cookie")]}
    name, morsel = next(iter(jar.items()))
    sensitive = any(h in name.lower() for h in SESSION_HINTS)
    issues: list[tuple[str, str]] = []

    if not morsel["secure"]:
        issues.append(("HIGH" if sensitive else "MEDIUM", "Missing Secure flag: cookie may travel over plain HTTP"))
    if not morsel["httponly"]:
        issues.append(("HIGH" if sensitive else "LOW", "Missing HttpOnly flag: JavaScript (and thus XSS) can read it"))
    samesite = morsel["samesite"].lower()
    if not samesite:
        issues.append(("MEDIUM", "No SameSite attribute: browser default applies; set Lax or Strict explicitly"))
    elif samesite == "none" and not morsel["secure"]:
        issues.append(("HIGH", "SameSite=None requires Secure (browsers reject it otherwise)"))
    elif samesite == "none":
        issues.append(("LOW", "SameSite=None: cookie is sent on cross-site requests (CSRF exposure)"))
    if name.startswith("__Host-") and not (morsel["secure"] and morsel["path"] == "/" and not morsel["domain"]):
        issues.append(("HIGH", "__Host- prefix requires Secure, Path=/, and no Domain"))
    if name.startswith("__Secure-") and not morsel["secure"]:
        issues.append(("HIGH", "__Secure- prefix requires the Secure flag"))
    if morsel["domain"] and morsel["domain"].count(".") <= 1 and not morsel["domain"].startswith("."):
        issues.append(("LOW", f"Domain={morsel['domain']} shares the cookie with all subdomains"))
    max_age = morsel["max-age"]
    if sensitive and max_age.isdigit() and int(max_age) > 30 * 86400:
        issues.append(("MEDIUM", f"Long-lived sensitive cookie ({int(max_age) // 86400} days)"))
    if not is_https:
        issues.append(("INFO", "Received over HTTP; the whole exchange is sniffable"))
    return {"name": name, "sensitive": sensitive, "issues": issues}


def collect_set_cookie_headers(response) -> list[tuple[str, str]]:
    """Gather Set-Cookie headers from every hop (redirects often set cookies too)."""
    out = []
    for hop in list(response.history) + [response]:
        raw = hop.raw.headers.getlist("Set-Cookie") if hasattr(hop.raw.headers, "getlist") else []
        out += [(hop.url, h) for h in raw]
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit the cookies a site sets.")
    parser.add_argument("url")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    try:
        import requests
        url = normalize_url(args.url)
        resp = requests.get(url, timeout=args.timeout, headers={"User-Agent": "cyber-toolkit-cookie-audit/1.0"})
    except ValueError as exc:
        sys.exit(f"Error: {exc}")
    except requests.RequestException as exc:
        sys.exit(f"Request failed: {exc}")

    headers = collect_set_cookie_headers(resp)
    if not headers:
        print("No Set-Cookie headers received on this request (cookies may be set by JavaScript or after login).")
        return
    print(f"{len(headers)} cookie(s) set while loading {url}\n")
    for hop_url, raw in headers:
        result = audit_set_cookie(raw, hop_url.startswith("https://"))
        print(f"Cookie: {result['name']}" + ("   (looks session/auth related)" if result.get("sensitive") else ""))
        for sev, msg in result["issues"] or [("OK", "All recommended attributes present")]:
            print(f"   [{sev}] {msg}")
        print()


if __name__ == "__main__":
    main()
