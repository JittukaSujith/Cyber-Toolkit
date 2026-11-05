# Device Scanner

**Type:** GUI (Tkinter)  |  **Category:** Recon / Defensive

> **Authorized use only.** Run this only against systems you own or have explicit written permission to test.

## What it does
GUI that scans a private IP or CIDR with selectable port profiles, then guesses device type (printer, camera, Windows PC...) and highlights risky exposed services. Scans run in a background thread.

## What you will learn
- Service fingerprinting from open-port patterns
- Why IoT devices are a weak spot (default credentials, Telnet, no updates)
- Thread + queue pattern to keep a GUI responsive

## Usage
```bash
cd device_scanner
python device_scanner_gui.py
```

## Example output (illustrative)
```text
(GUI table)  192.168.1.20 | printer.lan | Printer | 631/ipp, 9100/jetdirect | -
```

## Try it yourself
- Scan only your own home network and disable services you do not need.
- Add mDNS / SSDP discovery for better device naming.

## Limitations
Device guesses are heuristics. Only private IPv4 ranges up to 256 addresses are allowed.
