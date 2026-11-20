# Cyber Toolkit: hands-on security tools in Python
markdown
![tests](https://github.com/JittukaSujith/cyber-toolkit/actions/workflows/tests.yml/badge.svg)

A learning portfolio of 16 small, readable cybersecurity tools. Each lives in its own folder with a short script, a README and comments that explain **the security idea** behind the code. Some are GUI, most are CLI, and they cover defensive, recon, crypto and educational offensive-style techniques.

## Ethical use and legal disclaimer

> **These tools are for education and for testing systems that you own or have explicit, written permission to test.**
>
> Scanning, probing or attacking systems without authorization may be illegal (for example under the US Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalent laws elsewhere), even if you mean no harm. You are solely responsible for how you use this code. The authors accept no liability for misuse or damage.
>
> Active tools (port scanner, LAN scanner, device scanner, web vulnerability scanner, open-redirect test) show an authorization banner and ask for confirmation, restrict LAN scans to private ranges, and cap request volume. These are guardrails, not a substitute for good judgment. Safe places to practise: your own machine and home network, local labs (DVWA, OWASP Juice Shop, the bundled demo server), and sites that explicitly invite testing.

## The tools

| # | Folder | Interface | Category | What it teaches |
|---|--------|-----------|----------|-----------------|
| 1 | `password_strength_checker` | GUI + CLI | Defensive | Entropy, wordlists, breach checks with k-anonymity |
| 2 | `email_spoof_check` | CLI | Recon / Defensive | SPF, DKIM, DMARC |
| 3 | `phishing_url_scanner` | CLI | Defensive | Phishing URL anatomy, homographs, defanging |
| 4 | `http_header_checker` | CLI | Recon / Defensive | HSTS, CSP, clickjacking and MIME-sniffing defences |
| 5 | `tls_certificate_analyzer` | CLI | Recon / Defensive | Certificates, trust chains, expiry and weak crypto |
| 6 | `ip_info_checker` | CLI | Recon | Private vs public ranges, reverse DNS, ASN |
| 7 | `lan_scanner` | CLI | Recon | Host discovery, ARP, asset inventory |
| 8 | `device_scanner` | GUI | Recon / Defensive | Service fingerprinting, IoT risk, threaded GUIs |
| 9 | `hash_checker` | GUI + CLI | Crypto | Integrity checks, broken hashes |
| 10 | `cookie_security_audit` | CLI | Web | Secure / HttpOnly / SameSite |
| 11 | `redirect_tester` | CLI | Web (offensive-style) | Redirect chains, open redirects |
| 12 | `web_vuln_scanner` | CLI + demo target | Web (offensive-style) | XSS, SQLi errors, misconfiguration |
| 13 | `port_scanner` | CLI | Recon (offensive-style) | TCP handshake, exposure, banners |
| 14 | `cipher_tools` | CLI | Crypto | Classic ciphers, frequency analysis, brute force |
| 15 | `aes_encryption` | GUI + CLI | Crypto | AES-GCM, scrypt, salts and nonces |
| 16 | `jwt_inspector` | CLI | Web / Auth | JWT structure, alg=none, weak secrets |

## Quick start

```bash
git clone https://github.com/JittukaSujith/cyber-toolkit.git cyber-toolkit && cd cyber-toolkit
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python jwt_inspector/jwt_inspector.py --demo --secret secret
python password_strength_checker/password_checker.py   # opens the GUI
```

Requirements: Python 3.10+. GUI tools need Tkinter (bundled with Python on Windows/macOS; on Debian/Ubuntu run `sudo apt install python3-tk`). Third-party libraries are small and standard: `requests`, `cryptography`, `dnspython`.



## Suggested learning path

1. **Foundations:** `hash_checker`, `password_strength_checker`, `cipher_tools`, `aes_encryption`
2. **Know your exposure (on your own network):** `ip_info_checker`, `port_scanner`, `lan_scanner`, `device_scanner`
3. **Web security basics:** `http_header_checker`, `cookie_security_audit`, `tls_certificate_analyzer`, `jwt_inspector`
4. **Email and phishing:** `email_spoof_check`, `phishing_url_scanner`
5. **Think like an attacker (in a lab):** `redirect_tester`, then `web_vuln_scanner` against the bundled demo server. Read the demo's source, fix its bugs, and re-scan.

## Project layout

```
cyber-toolkit/
├── common/              shared validation, authorization prompt, network helpers
├── <tool_name>/         one folder per tool
│   ├── <script>.py      core logic as small functions + a thin CLI/GUI layer
│   └── README.md        what it does, concepts, usage, exercises, limitations
├── tests/test_core.py   offline unit tests for each tool's pure logic
├── requirements.txt
└── LICENSE
```

Design conventions: logic lives in pure, testable functions; the CLI/GUI is a thin wrapper; all user input is validated (`common/validation.py`); GUI libraries and network libraries are imported lazily so modules stay importable in tests; every tool prints clear errors rather than stack traces.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests are offline and cover the parsing, scoring and crypto logic (including AES tamper detection and TLS certificate analysis on a generated certificate). The GUI layouts and live-network paths are not covered by automated tests.

## Ideas to extend it

- Add a `--json` output option to every CLI and a combined HTML report.
- Package it with `pyproject.toml` and a `cyber-toolkit <tool>` entry point.
- New tools: subdomain enumeration (passive), log analyzer for failed SSH logins, file-integrity monitor, steganography demo, simple honeypot.

## Disclaimer of warranty

Provided "as is" for educational purposes under the MIT License. These tools are simplified teaching aids; do not rely on them as your only security control.

## Author

Built by Sujith Kumar Jittuka ([@JittukaSujith](https://github.com/JittukaSujith)) as a hands-on learning and portfolio project for cybersecurity roles.
