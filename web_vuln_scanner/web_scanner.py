#!/usr/bin/env python3
"""
Basic Web Vulnerability Scanner (CLI): a small, NON-DESTRUCTIVE teaching scanner.

SECURITY IDEAS demonstrated (mapped to the OWASP Top 10):
  * Reflected XSS (A03 Injection)   - input echoed back unescaped lets an attacker run
    script in a victim's browser. We inject a harmless marker containing < > " and see
    whether it comes back unescaped. No script is ever executed.
  * SQL injection (A03)             - a lone quote may break a SQL query and surface a
    database error message. We look for well-known error signatures only.
  * Security misconfiguration (A05) - exposed /.git, /.env, directory listings, backups.
  * Insecure design/transport (A02/A04) - password forms over HTTP, POST forms with no
    anti-CSRF token.
Safety rails: same-origin only, request cap, delay between requests, GET-only testing
(POST forms are listed but not submitted since they may change data), and an
authorization prompt. Scanner findings are LEADS, not proof; always verify manually.

Practice target: run  `python demo_vulnerable_server.py`  in this folder (localhost only).
"""
from __future__ import annotations

import argparse
import pathlib
import re
import secrets
import sys
import time
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from common.consent import add_permission_flag, require_authorization  # noqa: E402
from common.validation import normalize_url  # noqa: E402

SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "pg_query()", "sqlite3.operationalerror",
    "sqlstate[", "odbc sql server driver", "ora-01756", "syntax error at or near",
]
SENSITIVE_PATHS = {  # path -> (substring that must appear to avoid false positives, severity)
    "/.git/HEAD": ("ref:", "HIGH"),
    "/.env": ("=", "HIGH"),
    "/backup.zip": (None, "MEDIUM"),
    "/phpinfo.php": ("phpinfo", "MEDIUM"),
    "/server-status": ("apache", "MEDIUM"),
    "/admin/": (None, "INFO"),
    "/robots.txt": ("disallow", "INFO"),
}


class PageParser(HTMLParser):
    """Collect links and forms from HTML."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            self._form["inputs"].append({"name": a["name"], "type": a.get("type", "text").lower(), "value": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


class Scanner:
    def __init__(self, base_url: str, delay: float, max_requests: int, timeout: float = 8):
        import requests
        self.base = base_url
        self.origin = urlparse(base_url).netloc
        self.delay, self.max_requests, self.timeout = delay, max_requests, timeout
        self.requests_made = 0
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "cyber-toolkit-web-scanner/1.0 (educational)"
        self.findings: list[tuple[str, str, str]] = []  # (severity, title, evidence)

    def get(self, url: str):
        if self.requests_made >= self.max_requests:
            return None
        if urlparse(url).netloc != self.origin:  # never leave the authorized scope
            return None
        self.requests_made += 1
        time.sleep(self.delay)
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except Exception:
            return None

    def add(self, severity: str, title: str, evidence: str) -> None:
        if (severity, title, evidence) not in self.findings:
            self.findings.append((severity, title, evidence))

    # ---- discovery ----
    def crawl(self, limit: int = 15) -> tuple[list[str], list[tuple[str, dict]]]:
        queue, seen, forms = [self.base], set(), []
        while queue and len(seen) < limit:
            url = queue.pop(0).split("#")[0]
            if url in seen:
                continue
            seen.add(url)
            resp = self.get(url)
            if resp is None or "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            parser = PageParser()
            parser.feed(resp.text)
            forms += [(url, f) for f in parser.forms]
            for link in parser.links:
                full = urljoin(url, link)
                if urlparse(full).netloc == self.origin and urlparse(full).scheme in ("http", "https"):
                    queue.append(full)
        return sorted(seen), forms

    # ---- checks ----
    def check_reflection_and_sqli(self, url: str, params: list[str]) -> None:
        parts = urlsplit(url)
        base_query = dict(parse_qsl(parts.query))
        for param in params:
            marker = "xss" + secrets.token_hex(3)
            for label, payload in (("xss", f'{marker}<"\'>'), ("sqli", "'")):
                query = {**base_query, param: payload}
                test_url = urlunsplit(parts._replace(query=urlencode(query)))
                resp = self.get(test_url)
                if resp is None:
                    continue
                body = resp.text
                if label == "xss" and f'{marker}<"\'>' in body:
                    self.add("HIGH", "Possible reflected XSS", f"parameter '{param}' at {parts.path or '/'} reflects < > \" ' unescaped")
                elif label == "xss" and marker in body:
                    self.add("INFO", "Input reflected (appears encoded)", f"parameter '{param}' at {parts.path or '/'}")
                if label == "sqli" and any(sig in body.lower() for sig in SQL_ERRORS):
                    self.add("HIGH", "Possible SQL injection (database error shown)", f"parameter '{param}' at {parts.path or '/'}")

    def check_forms(self, forms: list[tuple[str, dict]]) -> None:
        for page, form in forms:
            action = urljoin(page, form["action"] or page)
            names = [i["name"] for i in form["inputs"]]
            has_pw = any(i["type"] == "password" for i in form["inputs"])
            if has_pw and urlparse(action).scheme == "http":
                self.add("HIGH", "Password form submits over HTTP", f"form on {page} -> {action}")
            if form["method"] == "post" and not any(re.search(r"csrf|token|nonce", n, re.I) for n in names):
                self.add("MEDIUM", "POST form without visible anti-CSRF token", f"form on {page} (fields: {', '.join(names) or 'none'})")
            if form["method"] == "get" and names:
                self.check_reflection_and_sqli(action, [i["name"] for i in form["inputs"] if i["type"] in ("text", "search", "")])
            elif form["method"] == "post":
                self.add("INFO", "POST form not tested (could change data)", f"{action}")

    def check_sensitive_paths(self) -> None:
        root = f"{urlparse(self.base).scheme}://{self.origin}"
        for path, (needle, severity) in SENSITIVE_PATHS.items():
            resp = self.get(root + path)
            if resp is not None and resp.status_code == 200 and (needle is None or needle in resp.text[:2000].lower()):
                self.add(severity, f"Exposed resource {path}", f"{root + path} returned HTTP 200")

    def check_page_basics(self, pages: list[str]) -> None:
        for url in pages[:5]:
            resp = self.get(url)
            if resp is None:
                continue
            if "Index of /" in resp.text[:1000]:
                self.add("MEDIUM", "Directory listing enabled", url)
            if "traceback (most recent call last)" in resp.text.lower() or "stack trace" in resp.text.lower():
                self.add("MEDIUM", "Verbose error / stack trace disclosed", url)
            for header in ("X-Powered-By", "Server"):
                if re.search(r"\d", resp.headers.get(header, "")):
                    self.add("LOW", "Software version disclosed", f"{header}: {resp.headers[header]}")
            if "content-security-policy" not in {k.lower() for k in resp.headers}:
                self.add("LOW", "No Content-Security-Policy header", url)

    def run(self) -> None:
        print("[*] Crawling same-origin pages...")
        pages, forms = self.crawl()
        print(f"    {len(pages)} page(s), {len(forms)} form(s) found")
        print("[*] Testing URL parameters...")
        for page in pages:
            params = list(dict(parse_qsl(urlsplit(page).query)))
            if params:
                self.check_reflection_and_sqli(page, params)
        print("[*] Testing forms...")
        self.check_forms(forms)
        print("[*] Looking for exposed files and misconfigurations...")
        self.check_sensitive_paths()
        self.check_page_basics(pages)


def main() -> None:
    parser = argparse.ArgumentParser(description="Small non-destructive web vulnerability scanner (educational).")
    parser.add_argument("url", help="start URL, e.g. http://127.0.0.1:8081/")
    parser.add_argument("--delay", type=float, default=0.2, help="seconds between requests (default 0.2)")
    parser.add_argument("--max-requests", type=int, default=150, help="hard request cap (default 150)")
    add_permission_flag(parser)
    args = parser.parse_args()
    try:
        url = normalize_url(args.url, default_scheme="http")
        if not 0 <= args.delay <= 10 or not 1 <= args.max_requests <= 1000:
            raise ValueError("delay must be 0-10 and max-requests 1-1000")
    except ValueError as exc:
        sys.exit(f"Error: {exc}")

    require_authorization(url, args.i_have_permission)
    scanner = Scanner(url, args.delay, args.max_requests)
    scanner.run()

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    print(f"\n{'=' * 60}\nFindings ({scanner.requests_made} requests sent)\n{'=' * 60}")
    for sev, title, evidence in sorted(scanner.findings, key=lambda f: order[f[0]]) or [("OK", "Nothing found", "")]:
        print(f"[{sev:<6}] {title}\n         {evidence}")
    print("\nReminder: automated results can be false positives/negatives. Verify manually.")


if __name__ == "__main__":
    main()
