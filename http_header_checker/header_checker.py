#!/usr/bin/env python3
"""
HTTP Security Header Checker (CLI)

SECURITY IDEA: Browsers enforce many protections only when the server asks for them
via response headers:
  * Strict-Transport-Security : force HTTPS, defeats SSL-stripping
  * Content-Security-Policy   : limits where scripts load from, mitigates XSS
  * X-Frame-Options / CSP frame-ancestors : stops clickjacking
  * X-Content-Type-Options    : stops MIME-sniffing attacks
  * Referrer-Policy / Permissions-Policy : limit data leakage and powerful features
Headers like Server / X-Powered-By leak software versions that help attackers.
This tool sends one normal GET request and grades what comes back.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from common.validation import normalize_url  # noqa: E402

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]


def evaluate_headers(headers: dict[str, str], is_https: bool = True) -> list[dict]:
    """Pure function (easy to test): returns a list of findings with status pass/warn/fail."""
    h = {k.lower(): v for k, v in headers.items()}
    findings: list[dict] = []

    def add(name, status, detail, points):
        findings.append({"header": name, "status": status, "detail": detail, "points": points})

    # HSTS
    hsts = h.get("strict-transport-security")
    if not is_https:
        add("Strict-Transport-Security", "fail", "Site served over plain HTTP", 0)
    elif not hsts:
        add("Strict-Transport-Security", "fail", "Missing: browsers may be downgraded to HTTP", 0)
    else:
        max_age = next((int(p.split("=")[1]) for p in hsts.replace(" ", "").split(";")
                        if p.lower().startswith("max-age=") and p.split("=")[1].isdigit()), 0)
        if max_age < 15_552_000:
            add("Strict-Transport-Security", "warn", f"max-age={max_age} is short (use >= 31536000)", 10)
        else:
            add("Strict-Transport-Security", "pass", hsts, 20)

    # CSP
    csp = h.get("content-security-policy")
    if not csp:
        add("Content-Security-Policy", "fail", "Missing: no browser-enforced XSS mitigation", 0)
    elif "unsafe-inline" in csp or "unsafe-eval" in csp or "default-src *" in csp:
        add("Content-Security-Policy", "warn", "Present but permits unsafe-inline/unsafe-eval/wildcards", 12)
    else:
        add("Content-Security-Policy", "pass", csp[:80] + ("..." if len(csp) > 80 else ""), 25)

    # Clickjacking
    xfo = h.get("x-frame-options", "").upper()
    if xfo in ("DENY", "SAMEORIGIN") or "frame-ancestors" in (csp or ""):
        add("X-Frame-Options / frame-ancestors", "pass", xfo or "set via CSP", 15)
    else:
        add("X-Frame-Options / frame-ancestors", "fail", "Missing: page may be framed (clickjacking)", 0)

    # MIME sniffing
    if h.get("x-content-type-options", "").lower() == "nosniff":
        add("X-Content-Type-Options", "pass", "nosniff", 10)
    else:
        add("X-Content-Type-Options", "fail", "Missing 'nosniff'", 0)

    # Referrer / permissions
    if "referrer-policy" in h:
        add("Referrer-Policy", "pass", h["referrer-policy"], 10)
    else:
        add("Referrer-Policy", "warn", "Missing: full URLs may leak to other sites", 0)
    if "permissions-policy" in h:
        add("Permissions-Policy", "pass", h["permissions-policy"][:60], 5)
    else:
        add("Permissions-Policy", "warn", "Missing: camera/mic/geolocation not restricted", 0)

    # Information disclosure
    leaks = {n: h[n.lower()] for n in LEAKY_HEADERS if n.lower() in h}
    if leaks:
        add("Information disclosure", "warn", "; ".join(f"{k}: {v}" for k, v in leaks.items()), 0)
    else:
        add("Information disclosure", "pass", "No version-leaking headers", 15)
    return findings


def grade(findings: list[dict]) -> tuple[int, str]:
    score = min(sum(f["points"] for f in findings), 100)
    letter = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"
    return score, letter


def main() -> None:
    parser = argparse.ArgumentParser(description="Check a site's HTTP security headers.")
    parser.add_argument("url", help="e.g. https://example.com")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    try:
        import requests
        url = normalize_url(args.url)
        resp = requests.get(url, timeout=args.timeout, headers={"User-Agent": "cyber-toolkit-header-checker/1.0"})
    except ValueError as exc:
        sys.exit(f"Error: {exc}")
    except requests.RequestException as exc:
        sys.exit(f"Request failed: {exc}")

    findings = evaluate_headers(dict(resp.headers), resp.url.startswith("https://"))
    score, letter = grade(findings)
    if args.json:
        print(json.dumps({"url": resp.url, "status": resp.status_code, "score": score, "grade": letter, "findings": findings}, indent=2))
        return

    print(f"URL: {resp.url}  (HTTP {resp.status_code})\n")
    icons = {"pass": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]"}
    for f in findings:
        print(f"{icons[f['status']]} {f['header']:<36} {f['detail']}")
    print(f"\nScore: {score}/100   Grade: {letter}")


if __name__ == "__main__":
    main()
