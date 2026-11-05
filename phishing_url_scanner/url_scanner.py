#!/usr/bin/env python3
"""
Phishing URL Scanner (CLI): static, heuristic analysis of a URL.

SECURITY IDEA: Phishing URLs often carry tell-tale signs: raw IP hosts, '@' tricks,
look-alike (punycode) domains, brand names in subdomains, throwaway TLDs, urgent
keywords. This tool NEVER visits the URL; it only inspects the text, so it is safe
to run on suspicious links. It is a teaching heuristic, not a replacement for
threat-intel feeds (e.g. Google Safe Browsing, PhishTank).
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
from urllib.parse import unquote, urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from common.validation import is_valid_ip  # noqa: E402

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "work", "support", "rest"}
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "password", "confirm", "bank", "wallet", "invoice", "suspend"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
BRANDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook", "instagram", "bankofamerica", "chase", "dropbox", "docusign"]


def defang(url: str) -> str:
    """Make a URL unclickable for safe sharing in reports/chats (hxxps://evil[.]com)."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def registered_domain(host: str) -> str:
    # Simplification: last two labels. Real code should use the Public Suffix List
    # (e.g. the 'tldextract' library) to handle suffixes like .co.uk correctly.
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def analyze_url(url: str) -> tuple[int, list[tuple[int, str]]]:
    """Return (risk score 0-100, list of (points, reason))."""
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path_query = unquote(parsed.path + "?" + parsed.query).lower()
    reasons: list[tuple[int, str]] = []

    def flag(points: int, text: str) -> None:
        reasons.append((points, text))

    if parsed.scheme != "https":
        flag(10, "Not using HTTPS")
    if is_valid_ip(host):
        flag(30, "Host is a raw IP address instead of a domain name")
    if "@" in parsed.netloc:
        flag(30, "Contains '@' in the authority part: everything before it is ignored by browsers, a classic disguise")
    if host.startswith("xn--") or ".xn--" in host:
        flag(25, "Punycode (xn--) domain: may be a look-alike using foreign characters (homograph attack)")
    if any(ord(c) > 127 for c in host):
        flag(25, "Non-ASCII characters in hostname (possible homograph attack)")
    if host in SHORTENERS:
        flag(15, "URL shortener hides the real destination")
    if host.count(".") >= 4:
        flag(15, f"Many subdomain levels ({host.count('.')} dots)")
    if host.count("-") >= 3:
        flag(10, "Many hyphens in the domain name")
    if len(url) > 100:
        flag(10, f"Very long URL ({len(url)} characters)")
    if parsed.port not in (None, 80, 443):
        flag(10, f"Unusual port {parsed.port}")
    if "%" in parsed.netloc or (re.search(r"%[0-9a-f]{2}", parsed.path, re.I) and parsed.path.count("%") > 3):
        flag(10, "Heavy percent-encoding (may hide content)")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flag(15, f"TLD '.{tld}' is frequently abused for throwaway/phishing sites")
    hits = [k for k in KEYWORDS if k in host + path_query]
    if hits:
        flag(min(5 * len(hits), 20), f"Urgency/credential keywords: {', '.join(hits)}")

    reg = registered_domain(host)
    for brand in BRANDS:
        if brand in host and brand not in reg.split(".")[0]:
            flag(30, f"Brand '{brand}' appears in the subdomain but the real domain is '{reg}' (impersonation)")
            break
        if brand in reg.split(".")[0] and reg.split(".")[0] != brand and not is_valid_ip(host):
            flag(20, f"Domain '{reg}' contains brand '{brand}' but is not the official domain (typosquat/combosquat)")
            break
    return min(sum(p for p, _ in reasons), 100), reasons


def verdict(score: int) -> str:
    return "HIGH RISK" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LOW RISK (not proof of safety)"


def main() -> None:
    parser = argparse.ArgumentParser(description="Heuristic phishing URL analysis (never visits the URL).")
    parser.add_argument("urls", nargs="*", help="one or more URLs to analyse")
    parser.add_argument("-f", "--file", help="text file with one URL per line")
    args = parser.parse_args()

    urls = list(args.urls)
    if args.file:
        try:
            urls += [l.strip() for l in pathlib.Path(args.file).read_text().splitlines() if l.strip()]
        except OSError as exc:
            sys.exit(f"Error reading file: {exc}")
    if not urls:
        parser.error("provide at least one URL or --file")

    for url in urls:
        score, reasons = analyze_url(url)
        print(f"\n{defang(url)}\n  Risk score: {score}/100 -> {verdict(score)}")
        for points, text in reasons:
            print(f"   +{points:<3} {text}")
        if not reasons:
            print("   No heuristic red flags found.")


if __name__ == "__main__":
    main()
