# LAN Scanner

**Type:** CLI  |  **Category:** Recon / Asset discovery

> **Authorized use only.** Run this only against systems you own or have explicit written permission to test.

## What it does
Finds live hosts on a private network using unprivileged TCP probes plus the OS ARP cache (MAC addresses). Refuses public ranges and anything larger than a /22.

## What you will learn
- Asset discovery as step zero of defence
- ARP is layer-2 and only works on the local subnet
- Why ICMP ping needs raw sockets and what to do without them

## Usage
```bash
cd lan_scanner
python lan_scanner.py                       # auto-detect your /24
python lan_scanner.py --cidr 192.168.1.0/24 --i-have-permission
```

## Example output (illustrative)
```text
IP              MAC                 HOSTNAME
192.168.1.1     aa:bb:cc:dd:ee:ff   router.lan
```

## Try it yourself
- Do you recognise every device? Investigate any you do not.
- Add MAC vendor (OUI) lookup.

## Limitations
Hosts that firewall every probed port and are not in the ARP cache will not appear.
