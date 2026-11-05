#!/usr/bin/env python3
"""
Password Strength Checker  (GUI by default, --cli for terminal)

SECURITY IDEA: Password strength is about how many guesses an attacker needs.
  * Entropy ~= length * log2(character pool size). More length beats more symbols.
  * But entropy math assumes random characters. Humans pick "Password123!", which is
    in every cracking wordlist, so we also check common passwords and simple patterns.
  * Your password is analysed locally only. It is never stored or sent anywhere
    (the optional --hibp check sends only the first 5 chars of a SHA-1 hash).
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import math
import string
import sys

# A tiny sample; real wordlists (e.g. rockyou.txt) hold millions of entries.
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "qwerty", "abc123", "letmein",
    "monkey", "dragon", "111111", "iloveyou", "admin", "welcome", "login",
    "football", "baseball", "master", "sunshine", "princess", "passw0rd",
    "password1", "password123", "qwerty123", "1q2w3e4r", "trustno1", "zaq12wsx",
}
KEYBOARD_WALKS = ["qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx", "123456", "654321"]
LEET = str.maketrans("@4310$5!7", "aaeioss1t")  # p@ssw0rd -> password
GUESSES_PER_SECOND = 1e10  # offline attack on a fast hash (e.g. unsalted MD5) with GPUs


def pool_size(password: str) -> int:
    pool = 0
    if any(c in string.ascii_lowercase for c in password): pool += 26
    if any(c in string.ascii_uppercase for c in password): pool += 26
    if any(c in string.digits for c in password): pool += 10
    if any(c in string.punctuation for c in password): pool += len(string.punctuation)
    if any(ord(c) > 127 or c == " " for c in password): pool += 32
    return pool


def has_sequence(password: str, run: int = 4) -> bool:
    """Detect runs like 'abcd', '4321' or 'aaaa'."""
    p = password.lower()
    for i in range(len(p) - run + 1):
        chunk = p[i:i + run]
        diffs = {ord(chunk[j + 1]) - ord(chunk[j]) for j in range(run - 1)}
        if diffs in ({1}, {-1}, {0}):
            return True
    return False


def format_duration(seconds: float) -> str:
    if seconds < 1: return "instantly"
    for unit, size in (("years", 31_536_000), ("days", 86_400), ("hours", 3_600), ("minutes", 60)):
        if seconds >= size:
            value = seconds / size
            return f"{value:,.0f} {unit}" if value < 1e9 else "billions of years"
    return f"{seconds:.0f} seconds"


def analyze(password: str) -> dict:
    """Return score (0-4), label, entropy, crack-time estimate, and feedback."""
    if not password:
        return {"score": 0, "label": "Empty", "entropy": 0.0, "crack_time": "instantly", "feedback": ["Enter a password."]}

    feedback: list[str] = []
    entropy = len(password) * math.log2(max(pool_size(password), 1))

    if password.lower() in COMMON_PASSWORDS or password.lower().translate(LEET) in COMMON_PASSWORDS:
        feedback.append("This is a very common password (even with 'leet' substitutions). Attackers try these first.")
        entropy = min(entropy, 10)
    if any(w in password.lower() for w in KEYBOARD_WALKS):
        feedback.append("Contains a keyboard pattern (e.g. 'qwerty').")
        entropy *= 0.6
    if has_sequence(password):
        feedback.append("Contains a sequence or repeated characters (e.g. 'abcd', '1111').")
        entropy *= 0.7
    if len(set(password)) <= len(password) // 2:
        feedback.append("Many repeated characters reduce strength.")
        entropy *= 0.8
    if len(password) < 12:
        feedback.append("Use at least 12 characters; length matters most.")
    if len(password) >= 12 and pool_size(password) < 52:
        feedback.append("Mix upper/lower case, digits, and symbols, or use a longer passphrase.")

    crack_seconds = (2 ** entropy) / GUESSES_PER_SECOND / 2  # on average, half the space
    thresholds = [28, 36, 60, 80]
    score = sum(entropy >= t for t in thresholds)
    labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
    if not feedback:
        feedback.append("Looks good. Store it in a password manager and enable MFA.")
    return {"score": score, "label": labels[score], "entropy": round(entropy, 1),
            "crack_time": format_duration(crack_seconds), "feedback": feedback}


def hibp_count(password: str) -> int:
    """
    Check Have I Been Pwned using k-anonymity.

    SECURITY IDEA: We send only the first 5 hex chars of the SHA-1 hash. The server
    returns every hash suffix sharing that prefix and WE compare locally, so the
    service never learns the password (or even its full hash).
    """
    import requests  # imported lazily so the GUI works without it
    digest = hashlib.sha1(password.encode()).hexdigest().upper()  # SHA-1 is required by the API
    prefix, suffix = digest[:5], digest[5:]
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
    resp.raise_for_status()
    for line in resp.text.splitlines():
        candidate, _, count = line.partition(":")
        if candidate == suffix:
            return int(count)
    return 0


def run_cli(use_hibp: bool) -> None:
    password = getpass.getpass("Password to test (hidden): ")
    result = analyze(password)
    print(f"\nStrength : {result['label']} ({result['score']}/4)")
    print(f"Entropy  : ~{result['entropy']} bits")
    print(f"Crack est: {result['crack_time']} at {GUESSES_PER_SECOND:.0e} guesses/sec (offline, fast hash)")
    for tip in result["feedback"]:
        print(f"  - {tip}")
    if use_hibp:
        try:
            count = hibp_count(password)
            print(f"\nBreach check: {'FOUND in %s known breaches - do not use it!' % f'{count:,}' if count else 'not found in known breaches.'}")
        except Exception as exc:  # network errors are expected sometimes
            print(f"\nBreach check failed: {exc}")


def run_gui() -> None:
    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError:
        sys.exit("tkinter is not available. Install it (e.g. 'sudo apt install python3-tk') or use --cli.")

    colors = ["#c0392b", "#e67e22", "#f1c40f", "#27ae60", "#1e8449"]
    root = tk.Tk()
    root.title("Password Strength Checker")
    root.geometry("460x340")
    root.resizable(False, False)

    frame = ttk.Frame(root, padding=16)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="Type a password (analysed locally, never stored):").pack(anchor="w")

    var = tk.StringVar()
    entry = ttk.Entry(frame, textvariable=var, show="*", width=48)
    entry.pack(pady=6)
    entry.focus()

    show_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(frame, text="Show password", variable=show_var,
                    command=lambda: entry.config(show="" if show_var.get() else "*")).pack(anchor="w")

    bar = tk.Canvas(frame, width=420, height=18, bg="#dddddd", highlightthickness=0)
    bar.pack(pady=8)
    rect = bar.create_rectangle(0, 0, 0, 18, width=0, fill=colors[0])
    summary = ttk.Label(frame, text="", font=("TkDefaultFont", 11, "bold"))
    summary.pack(anchor="w")
    detail = ttk.Label(frame, text="", wraplength=420, justify="left")
    detail.pack(anchor="w", pady=6)

    def update(*_):
        result = analyze(var.get())
        width = 420 * (result["score"] + 1) / 5 if var.get() else 0
        bar.coords(rect, 0, 0, width, 18)
        bar.itemconfig(rect, fill=colors[result["score"]])
        summary.config(text=f"{result['label']}  |  ~{result['entropy']} bits  |  crack: {result['crack_time']}")
        detail.config(text="\n".join(f"- {t}" for t in result["feedback"]))

    var.trace_add("write", update)
    update()
    root.mainloop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Password strength checker (GUI by default).")
    parser.add_argument("--cli", action="store_true", help="use the terminal instead of the GUI")
    parser.add_argument("--hibp", action="store_true", help="(CLI) also check Have I Been Pwned via k-anonymity")
    args = parser.parse_args()
    run_cli(args.hibp) if args.cli else run_gui()


if __name__ == "__main__":
    main()
