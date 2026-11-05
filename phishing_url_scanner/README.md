# Phishing URL Scanner

**Type:** CLI  |  **Category:** Defensive / Analysis

## What it does
Scores URLs with heuristics (raw IPs, '@' tricks, punycode, brand impersonation, odd TLDs, keywords). It never connects to the URL, so it is safe on live phishing links. Output is defanged.

## What you will learn
- Anatomy of a URL: scheme, userinfo, host, path
- Homograph and typosquatting attacks
- Defanging (hxxps://evil[.]com) for safe reporting

## Usage
```bash
cd phishing_url_scanner
python url_scanner.py http://paypal.secure-login.example.xyz/verify
python url_scanner.py -f urls.txt
```

## Example output (illustrative)
```text
hxxp://paypal[.]secure-login[.]verify-account[.]xyz/update
  Risk score: 75/100 -> HIGH RISK
   +30  Brand 'paypal' appears in the subdomain but the real domain is 'verify-account.xyz'
```

## Try it yourself
- Feed it 20 legitimate and 20 phishing URLs from public feeds and tune the weights.
- Replace registered_domain() with the tldextract library.

## Limitations
Heuristics produce false positives and negatives. Pair with real threat intelligence (Google Safe Browsing, PhishTank).
