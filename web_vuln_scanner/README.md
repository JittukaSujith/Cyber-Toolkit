# Basic Web Vulnerability Scanner

**Type:** CLI (+ local practice target)  |  **Category:** Web / Offensive-style (educational)

> **Authorized use only.** Run this only against systems you own or have explicit written permission to test.

## What it does
A small, non-destructive scanner. It crawls same-origin pages, probes GET parameters for reflected-input and SQL-error leaks, lists forms (flags password forms over HTTP and POST forms with no CSRF token), and checks for exposed files such as /.git/HEAD and /.env.

## What you will learn
- Reflected XSS and SQL injection as input-handling failures
- Security misconfiguration (exposed files, verbose errors, version banners)
- Why scanners give leads, not proof
- Scoping, rate-limiting and request caps as responsible-testing habits

## Usage
```bash
cd web_vuln_scanner
# 1. Start the deliberately vulnerable practice target (localhost only)
python demo_vulnerable_server.py

# 2. In another terminal, scan it
python web_scanner.py http://127.0.0.1:8081/ --i-have-permission
```

## Example output (illustrative)
```text
[HIGH  ] Possible reflected XSS
         parameter 'q' at /search reflects < > " ' unescaped
[HIGH  ] Possible SQL injection (database error shown)
         parameter 'id' at /item
```

## Try it yourself
- Open demo_vulnerable_server.py and fix each bug (html.escape, parameterised queries), then re-scan and watch the findings disappear.
- Practise on DVWA or OWASP Juice Shop running locally in Docker.
- Add a cookie-flag check or a CSP evaluator.

## Limitations
Not a replacement for tools such as OWASP ZAP or Burp Suite. POST forms are listed but never submitted; there is no JavaScript rendering or authentication support.
