# IP Info Checker

**Type:** CLI  |  **Category:** Recon

## What it does
Classifies an IP or hostname (private, loopback, link-local, public), shows reverse DNS and, for public addresses, enriches with ASN / org / location from ipinfo.io.

## What you will learn
- RFC 1918 private ranges and special-purpose addresses
- Reverse DNS (PTR) records
- Limits of IP geolocation, and the privacy cost of third-party lookups

## Usage
```bash
cd ip_info_checker
python ip_info.py 8.8.8.8
python ip_info.py github.com
python ip_info.py 10.0.0.5 --offline
```

## Example output (illustrative)
```text
Type         : Public (routable on the internet)
Reverse DNS  : dns.google
Org / ASN    : AS15169 Google LLC
```

## Try it yourself
- Look up the IPs in your own firewall or router logs.
- Add a local GeoLite2 database to work offline.

## Limitations
The online lookup uses a free third-party API that may rate-limit or change; use --offline to avoid sending addresses anywhere.
