# HTTP Header Checker

**Type:** CLI  |  **Category:** Recon / Defensive

## What it does
Fetches a page and grades its security headers (HSTS, CSP, frame protection, nosniff, Referrer-Policy, Permissions-Policy) and flags version-leaking headers.

## What you will learn
- How headers instruct browsers to enforce protections
- HSTS vs SSL stripping, CSP vs XSS, clickjacking defences
- Information disclosure via Server / X-Powered-By

## Usage
```bash
cd http_header_checker
python header_checker.py https://example.com
python header_checker.py example.com --json
```

## Example output (illustrative)
```text
[FAIL] Content-Security-Policy              Missing: no browser-enforced XSS mitigation
Score: 45/100   Grade: D
```

## Try it yourself
- Compare the grades of a bank, a news site and your own site.
- Add checks for Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy.

## Limitations
Only inspects headers of one response; a perfect grade does not mean the app is secure.
