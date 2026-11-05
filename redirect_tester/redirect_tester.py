#!/usr/bin/env python3
"""
Redirect Tester (CLI): trace redirect chains and test for open redirects.

SECURITY IDEAS:
  * Redirect chains: each hop is a chance for HTTPS->HTTP downgrade, tracking, or a
    hop through an untrusted domain. Long chains and loops are also a smell.
  * Open redirect: a parameter such as /login?next=URL that sends users to ANY URL
    lets attackers craft links on a trusted domain that land victims on a phishing
    page ("https://trusted.com/login?next=https://evil.com"). It is also a building
    block for OAuth token theft. Fix: allow-list destinations, or use relative paths only.

We follow redirects MANUALLY (allow_redirects=False) so we can see every hop.
The open-redirect probe uses a harmless, non-resolving test domain and only runs after
you confirm authorization.
"""
from __future__ import annotations

import argparse
import pathlib
import sys
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from common.consent import add_permission_flag, require_authorization  # noqa: E402
from common.validation import normalize_url  # noqa: E402

CANARY_HOST = "redirect-test.invalid"  # .invalid is reserved and will never resolve
OPEN_REDIRECT_PAYLOADS = [f"https://{CANARY_HOST}", f"//{CANARY_HOST}", f"/\\{CANARY_HOST}", f"https:{CANARY_HOST}"]


def trace(url: str, max_hops: int = 10, timeout: float = 8) -> list[dict]:
    import requests
    session = requests.Session()
    session.headers["User-Agent"] = "cyber-toolkit-redirect-tester/1.0"
    hops, seen = [], set()
    for _ in range(max_hops + 1):
        resp = session.get(url, allow_redirects=False, timeout=timeout)
        location = resp.headers.get("Location")
        hops.append({"url": url, "status": resp.status_code, "location": urljoin(url, location) if location else None})
        if not (300 <= resp.status_code < 400 and location):
            break
        url = urljoin(url, location)
        if url in seen:
            hops[-1]["loop"] = True
            break
        seen.add(url)
    return hops


def analyze_chain(hops: list[dict], max_hops: int = 10) -> list[str]:
    notes = []
    if len(hops) - 1 >= max_hops:
        notes.append("Hop limit reached: very long chain or redirect loop")
    if any(h.get("loop") for h in hops):
        notes.append("Redirect LOOP detected")
    for h in hops:
        if h["location"]:
            a, b = urlparse(h["url"]), urlparse(h["location"])
            if a.scheme == "https" and b.scheme == "http":
                notes.append(f"HTTPS->HTTP downgrade: {h['url']} -> {h['location']}")
            if a.hostname != b.hostname:
                notes.append(f"Cross-domain hop: {a.hostname} -> {b.hostname}")
    if len(hops) > 4:
        notes.append(f"{len(hops) - 1} redirects: chains this long hurt performance and add risk")
    return notes


def test_open_redirect(url: str, param: str, timeout: float = 8) -> list[tuple[str, str]]:
    """Inject canary URLs into `param`; report payloads whose Location points at the canary host."""
    import requests
    parts = urlsplit(url)
    findings = []
    for payload in OPEN_REDIRECT_PAYLOADS:
        query = [(k, v) for k, v in parse_qsl(parts.query) if k != param] + [(param, payload)]
        test_url = urlunsplit(parts._replace(query=urlencode(query)))
        resp = requests.get(test_url, allow_redirects=False, timeout=timeout, headers={"User-Agent": "cyber-toolkit-redirect-tester/1.0"})
        loc = resp.headers.get("Location", "")
        if 300 <= resp.status_code < 400 and urlparse(urljoin(test_url, loc)).hostname == CANARY_HOST:
            findings.append((payload, loc))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Trace redirects; optionally test a parameter for open redirect.")
    parser.add_argument("url")
    parser.add_argument("--max-hops", type=int, default=10)
    parser.add_argument("--param", help="query parameter to test for open redirect (e.g. next, url, redirect)")
    add_permission_flag(parser)
    args = parser.parse_args()

    try:
        import requests
        url = normalize_url(args.url)
        if not 1 <= args.max_hops <= 30:
            raise ValueError("max-hops must be between 1 and 30")
        if args.param:
            require_authorization(url, args.i_have_permission)
        hops = trace(url, args.max_hops)
        print("Redirect chain:")
        for i, h in enumerate(hops):
            print(f"  {i}. [{h['status']}] {h['url']}" + (f"\n        -> {h['location']}" if h["location"] else ""))
        print("\nObservations:")
        for note in analyze_chain(hops, args.max_hops) or ["No redirect problems found."]:
            print(f"  - {note}")
        if args.param:
            print(f"\nOpen redirect test on parameter '{args.param}':")
            found = test_open_redirect(url, args.param)
            if found:
                for payload, loc in found:
                    print(f"  [VULNERABLE] payload {payload!r} -> Location: {loc}")
                print("  Fix: validate destinations against an allow-list or only accept relative paths.")
            else:
                print("  No open redirect behaviour observed with the tested payloads (not proof of safety).")
    except ValueError as exc:
        sys.exit(f"Error: {exc}")
    except requests.RequestException as exc:
        sys.exit(f"Request failed: {exc}")


if __name__ == "__main__":
    main()
