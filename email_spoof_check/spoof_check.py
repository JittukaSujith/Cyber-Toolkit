#!/usr/bin/env python3
"""
Email Spoofing Check (CLI): can someone forge mail "From" this domain?

SECURITY IDEA: SMTP lets anyone type any "From" address. Three DNS-based controls
stop forgery:
  * SPF   - lists which servers may send mail for the domain.
  * DKIM  - cryptographic signature on each message (public key published in DNS).
  * DMARC - tells receivers what to do when SPF/DKIM fail (none/quarantine/reject).
A domain is easy to spoof when SPF is missing/permissive and DMARC is absent or p=none.
This tool only performs ordinary DNS lookups; it sends no email.

Requires: dnspython (pip install dnspython)
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from common.validation import validate_domain  # noqa: E402

COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "s1", "s2", "mail", "dkim"]


def txt_records(name: str) -> list[str]:
    """Return TXT strings for `name` (empty list if none)."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        sys.exit("dnspython is required: pip install dnspython")
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        print(f"[!] DNS timeout looking up {name}")
        return []
    # A TXT record may be split into several 255-byte chunks; join them.
    return ["".join(part.decode() for part in rdata.strings) for rdata in answers]


def parse_spf(record: str) -> dict:
    terms = record.split()[1:]
    qualifier = None
    for t in terms:
        if t.lstrip("+-~?") == "all":
            qualifier = t[0] if t[0] in "+-~?" else "+"
    return {
        "all": qualifier,
        "includes": [t.split(":", 1)[1] for t in terms if t.startswith("include:")],
        "lookups": sum(t.startswith(("include:", "a", "mx", "ptr", "exists:", "redirect=")) for t in terms),
    }


def parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        key, _, value = part.strip().partition("=")
        if key:
            tags[key.lower()] = value.strip()
    return tags


def analyze_spf(records: list[str]) -> list[tuple[str, str]]:
    """Return a list of (severity, message)."""
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return [("HIGH", "No SPF record: any server can claim to send for this domain.")]
    if len(spf) > 1:
        return [("HIGH", "Multiple SPF records: this is invalid and receivers may ignore SPF.")]
    info = parse_spf(spf[0])
    findings = [("INFO", f"SPF record: {spf[0]}")]
    verdicts = {
        "-": ("OK", "SPF ends in -all (hard fail): unauthorized senders should be rejected."),
        "~": ("MEDIUM", "SPF ends in ~all (soft fail): spoofed mail is often still delivered."),
        "?": ("HIGH", "SPF ends in ?all (neutral): offers no protection."),
        "+": ("HIGH", "SPF ends in +all: ANY server is authorized. Effectively no protection."),
        None: ("MEDIUM", "SPF has no 'all' mechanism, so there is no default policy."),
    }
    findings.append(verdicts[info["all"]])
    if info["lookups"] > 10:
        findings.append(("MEDIUM", f"SPF needs ~{info['lookups']} DNS lookups; the limit is 10 (permerror risk)."))
    return findings


def analyze_dmarc(records: list[str]) -> list[tuple[str, str]]:
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return [("HIGH", "No DMARC record: receivers have no policy for failed authentication.")]
    tags = parse_dmarc(dmarc[0])
    findings = [("INFO", f"DMARC record: {dmarc[0]}")]
    policy = tags.get("p", "").lower()
    if policy == "reject":
        findings.append(("OK", "DMARC policy is p=reject: strongest protection."))
    elif policy == "quarantine":
        findings.append(("LOW", "DMARC policy is p=quarantine: spoofed mail goes to spam. Consider p=reject."))
    else:
        findings.append(("HIGH", "DMARC policy is p=none: monitoring only, spoofed mail is still delivered."))
    if tags.get("pct", "100") != "100":
        findings.append(("MEDIUM", f"DMARC applies to only pct={tags['pct']}% of mail."))
    if "rua" not in tags:
        findings.append(("LOW", "No rua= reporting address; you will not receive aggregate reports."))
    return findings


def check_dkim(domain: str) -> list[str]:
    found = []
    for selector in COMMON_DKIM_SELECTORS:
        if any("p=" in r for r in txt_records(f"{selector}._domainkey.{domain}")):
            found.append(selector)
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description="Check a domain's SPF, DKIM and DMARC for spoofing risk.")
    parser.add_argument("domain", help="domain to check, e.g. example.com")
    args = parser.parse_args()
    try:
        domain = validate_domain(args.domain)
    except ValueError as exc:
        sys.exit(f"Error: {exc}")

    print(f"Email spoofing check for {domain}\n{'=' * 50}")
    results = analyze_spf(txt_records(domain)) + analyze_dmarc(txt_records(f"_dmarc.{domain}"))
    selectors = check_dkim(domain)
    if selectors:
        results.append(("OK", f"DKIM key(s) found for selector(s): {', '.join(selectors)}"))
    else:
        results.append(("INFO", "No DKIM key found at common selectors (the real selector may be custom)."))

    for severity, message in results:
        print(f"[{severity:<6}] {message}")

    high = sum(1 for s, _ in results if s == "HIGH")
    print("\nVerdict:", "LIKELY SPOOFABLE" if high >= 2 else "PARTIALLY PROTECTED" if high == 1 else "WELL PROTECTED")


if __name__ == "__main__":
    main()
