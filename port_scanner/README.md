# Port Scanner

**Type:** CLI  |  **Category:** Recon / Offensive-style (educational)

> **Authorized use only.** Run this only against systems you own or have explicit written permission to test.

## What it does
Threaded TCP connect scanner with port-spec parsing ('top', ranges, lists), service names, optional banner grabbing and notes on risky exposed services.

## What you will learn
- The TCP three-way handshake and what a 'connect scan' is
- Open vs closed vs filtered ports
- Banner grabbing and service exposure
- Why thread pools suit I/O-bound work

## Usage
```bash
cd port_scanner
python port_scanner.py 127.0.0.1
python port_scanner.py scanme.nmap.org -p 20-100 --banner --i-have-permission
```

## Example output (illustrative)
```text
PORT    SERVICE       NOTES
22      ssh
3389    rdp           RDP exposed (frequent brute-force target)
```

## Try it yourself
- Scan your own machine, then close an unneeded service and re-scan.
- Compare results with nmap -sT.
- Add a UDP scan mode for DNS (53).

## Limitations
Connect scans are noisy and slower than SYN scans. scanme.nmap.org is the Nmap project's public test host, but check its usage policy and keep scans light.
