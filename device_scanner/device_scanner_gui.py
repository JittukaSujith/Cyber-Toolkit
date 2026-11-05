#!/usr/bin/env python3
"""
Device Scanner (GUI): fingerprint devices by their open ports.

SECURITY IDEA: The set of open ports hints at what a device is (a printer listens on
9100, an IP camera on 554/RTSP, a Windows PC on 445/SMB). IoT devices are notoriously
under-patched and often ship with default passwords or cleartext services (Telnet),
so inventorying them on YOUR network is high-value defensive work.
The scan runs in a background thread and reports through a queue, because Tkinter
widgets must only be touched from the main thread.

ONLY scan networks you own or administer.
"""
from __future__ import annotations

import ipaddress
import pathlib
import queue
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from common.net import RISKY_PORTS, service_name, tcp_connect  # noqa: E402

PROFILES = {
    "Quick (common)": [22, 23, 53, 80, 135, 139, 443, 445, 554, 631, 1883, 3389, 5900, 8009, 8080, 9100, 62078],
    "Web only": [80, 443, 8000, 8080, 8443],
    "Remote admin": [22, 23, 3389, 5900],
}
MAX_HOSTS = 256


def guess_device(ports: set[int]) -> str:
    """Very rough heuristics. Real tools also use MAC vendor, banners, and mDNS."""
    if 9100 in ports or 631 in ports: return "Printer"
    if 554 in ports: return "IP camera / media device"
    if 8009 in ports: return "Chromecast / smart TV"
    if 62078 in ports: return "Apple iOS device"
    if 1883 in ports: return "IoT hub (MQTT)"
    if {135, 139, 445} & ports or 3389 in ports: return "Windows PC / server"
    if 22 in ports and 80 not in ports and 443 not in ports: return "Linux/Unix host"
    if 53 in ports and ({80, 443} & ports): return "Router / gateway"
    if {80, 443, 8080} & ports: return "Web-enabled device"
    return "Unknown"


def risk_notes(ports: set[int]) -> str:
    return "; ".join(RISKY_PORTS[p] for p in sorted(ports) if p in RISKY_PORTS)


def scan_host(ip: str, ports: list[int], timeout: float) -> tuple[str, list[int]]:
    return ip, [p for p in ports if tcp_connect(ip, p, timeout)]


def parse_targets(text: str) -> list[str]:
    text = text.strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError("Enter an IP (192.168.1.10) or CIDR range (192.168.1.0/24)")
    if net.version != 4 or not net.is_private:
        raise ValueError("Only private IPv4 ranges are allowed in this tool")
    if net.num_addresses > MAX_HOSTS:
        raise ValueError(f"Range too large (max {MAX_HOSTS} addresses)")
    return [str(h) for h in (net.hosts() if net.num_addresses > 1 else [net.network_address])]


def main() -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except ImportError:
        sys.exit("tkinter is not available. Install python3-tk (e.g. 'sudo apt install python3-tk').")

    root = tk.Tk()
    root.title("Device Scanner - authorized use only")
    root.geometry("860x460")
    top = ttk.Frame(root, padding=10)
    top.pack(fill="x")

    target_var, profile_var, status_var = tk.StringVar(value="192.168.1.0/24"), tk.StringVar(value="Quick (common)"), tk.StringVar(value="Idle")
    ttk.Label(top, text="Target (IP or CIDR):").pack(side="left")
    ttk.Entry(top, textvariable=target_var, width=20).pack(side="left", padx=6)
    ttk.Label(top, text="Profile:").pack(side="left")
    ttk.Combobox(top, textvariable=profile_var, values=list(PROFILES), state="readonly", width=16).pack(side="left", padx=6)
    scan_btn = ttk.Button(top, text="Scan")
    scan_btn.pack(side="left", padx=6)

    columns = ("ip", "host", "device", "ports", "risk")
    tree = ttk.Treeview(root, columns=columns, show="headings")
    for col, text, width in zip(columns, ("IP", "Hostname", "Likely device", "Open ports", "Risk notes"), (110, 160, 150, 170, 240)):
        tree.heading(col, text=text)
        tree.column(col, width=width)
    tree.pack(fill="both", expand=True, padx=10, pady=4)
    ttk.Label(root, textvariable=status_var).pack(anchor="w", padx=10, pady=4)

    results: queue.Queue = queue.Queue()

    def worker(targets, ports):
        with ThreadPoolExecutor(max_workers=64) as pool:
            for ip, open_ports in pool.map(lambda t: scan_host(t, ports, 0.5), targets):
                results.put(("host", ip, open_ports))
        results.put(("done", None, None))

    def poll():
        try:
            while True:
                kind, ip, open_ports = results.get_nowait()
                if kind == "done":
                    scan_btn.config(state="normal")
                    status_var.set(f"Done. {len(tree.get_children())} device(s) with open ports.")
                elif open_ports:
                    try:
                        name = socket.gethostbyaddr(ip)[0]
                    except OSError:
                        name = ""
                    ps = set(open_ports)
                    tree.insert("", "end", values=(ip, name, guess_device(ps),
                                                   ", ".join(f"{p}/{service_name(p)}" for p in open_ports), risk_notes(ps)))
        except queue.Empty:
            pass
        root.after(150, poll)

    def start():
        try:
            targets = parse_targets(target_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid target", str(exc))
            return
        if not messagebox.askyesno("Authorization", f"Do you own or have permission to scan {target_var.get()}?"):
            return
        tree.delete(*tree.get_children())
        scan_btn.config(state="disabled")
        status_var.set(f"Scanning {len(targets)} address(es)...")
        threading.Thread(target=worker, args=(targets, PROFILES[profile_var.get()]), daemon=True).start()

    scan_btn.config(command=start)
    poll()
    root.mainloop()


if __name__ == "__main__":
    main()
