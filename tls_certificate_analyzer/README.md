# TLS Certificate Analyzer

**Type:** CLI  |  **Category:** Recon / Defensive

## What it does
Downloads a server certificate, parses it (subject, issuer, validity, SANs, key type, signature hash) and separately performs a verifying handshake to show whether it is trusted and which TLS version was negotiated.

## What you will learn
- Chain of trust and what a CA vouches for
- Why expiry, hostname mismatch, self-signed certs and SHA-1 matter
- Why inspection (CERT_NONE) is not the same as trust

## Usage
```bash
cd tls_certificate_analyzer
pip install cryptography
python tls_analyzer.py example.com
python tls_analyzer.py example.com -p 8443
```

## Example output (illustrative)
```text
Valid      : 2026-01-01 -> 2026-04-01  (62 days left)
Trust      : TRUSTED by this system's CA store | TLSv1.3 | TLS_AES_256_GCM_SHA384
```

## Try it yourself
- Test https://expired.badssl.com, https://self-signed.badssl.com and https://wrong.host.badssl.com (public test sites made for this).
- Add certificate chain printing and OCSP/CT checks.

## Limitations
Only the leaf certificate is analysed; it does not test for cipher-suite weaknesses (use sslyze or testssl.sh for that).
