# Cookie Security Audit

**Type:** CLI  |  **Category:** Web / Defensive

## What it does
Reads every Set-Cookie header (including during redirects) and audits Secure, HttpOnly, SameSite, __Host-/__Secure- prefixes, scope and lifetime.

## What you will learn
- Cookies as bearer tokens
- How Secure, HttpOnly and SameSite mitigate sniffing, XSS theft and CSRF
- Cookie prefixes

## Usage
```bash
cd cookie_security_audit
python cookie_audit.py https://example.com
```

## Example output (illustrative)
```text
Cookie: sessionid   (looks session/auth related)
   [HIGH] Missing HttpOnly flag: JavaScript (and thus XSS) can read it
```

## Try it yourself
- Compare cookies before and after login using your browser dev tools for the real session.
- Add a flag for cookies set without a Max-Age or Expires.

## Limitations
Only sees cookies set on the first page load, not those set by JavaScript or after authentication.
