# Redirect Tester

**Type:** CLI  |  **Category:** Web / Offensive-style (educational)

> **Authorized use only.** Run this only against systems you own or have explicit written permission to test.

## What it does
Traces each hop of a redirect chain (flagging HTTPS to HTTP downgrades, cross-domain hops, loops) and can test a parameter for open redirects using a harmless non-resolving canary domain.

## What you will learn
- How redirects work (301/302/307/308, Location header)
- Open redirects as a phishing and OAuth-token-theft enabler
- Fixes: allow-lists and relative-only redirects

## Usage
```bash
cd redirect_tester
python redirect_tester.py http://github.com
python redirect_tester.py "https://yoursite.test/login" --param next --i-have-permission
```

## Example output (illustrative)
```text
  0. [301] http://github.com
        -> https://github.com/
  1. [200] https://github.com/
```

## Try it yourself
- Build a tiny Flask login with a vulnerable next= parameter, test it, then fix it with an allow-list.
- Add detection for JavaScript and meta-refresh redirects.

## Limitations
The open-redirect test only covers a few payload shapes and parameter-based Location redirects. Only use --param against your own apps.
