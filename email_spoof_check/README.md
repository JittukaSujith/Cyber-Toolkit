# Email Spoof Check

**Type:** CLI  |  **Category:** Recon / Defensive

## What it does
Looks up a domain's SPF, DMARC and common DKIM selectors via DNS and tells you how easy it is to forge mail from that domain.

## What you will learn
- SMTP does not authenticate the From address
- SPF qualifiers: -all vs ~all vs ?all vs +all
- DMARC policies none / quarantine / reject and why p=none is only monitoring
- The 10-DNS-lookup limit in SPF

## Usage
```bash
cd email_spoof_check
pip install dnspython
python spoof_check.py example.com
```

## Example output (illustrative)
```text
[HIGH  ] No DMARC record: receivers have no policy for failed authentication.
Verdict: PARTIALLY PROTECTED
```

## Try it yourself
- Check your own domain, your employer's and a few big brands.
- Add MTA-STS and BIMI lookups.

## Limitations
DKIM selectors are arbitrary, so a missing result at common selectors does not mean DKIM is absent. Only standard DNS queries are made.
