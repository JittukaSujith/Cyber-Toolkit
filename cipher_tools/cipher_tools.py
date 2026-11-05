#!/usr/bin/env python3
"""
Classic Cipher Toolkit (CLI): Caesar, Vigenere, Atbash, XOR, plus cracking helpers.

SECURITY IDEA: These ciphers are historical and INSECURE - never use them to protect
real data (use AES, see ../aes_encryption). They are valuable to learn because they show:
  * Kerckhoffs's principle: security must rest on the key, not on a secret algorithm.
  * Small key spaces fall to brute force (Caesar has only 25 useful keys).
  * Frequency analysis: substitution ciphers keep the statistical fingerprint of the
    language ('E' is the most common English letter), which is how we auto-crack Caesar.
  * Repeating-key XOR / Vigenere leak patterns when the key is shorter than the message.
"""
from __future__ import annotations

import argparse
import string
import sys
from collections import Counter

# Relative frequency (%) of letters in English text.
ENGLISH_FREQ = dict(zip(string.ascii_lowercase, [
    8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41,
    6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07]))


def _shift_char(ch: str, shift: int) -> str:
    if ch.isascii() and ch.isupper():
        return chr((ord(ch) - 65 + shift) % 26 + 65)
    if ch.isascii() and ch.islower():
        return chr((ord(ch) - 97 + shift) % 26 + 97)
    return ch  # leave digits, punctuation, spaces unchanged


def caesar(text: str, shift: int) -> str:
    return "".join(_shift_char(c, shift) for c in text)


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    shifts = [ord(k) - 97 for k in key.lower() if k.isascii() and k.isalpha()]
    if not shifts:
        raise ValueError("key must contain at least one letter (a-z)")
    out, i = [], 0
    for ch in text:
        if ch.isascii() and ch.isalpha():
            s = shifts[i % len(shifts)]
            out.append(_shift_char(ch, -s if decrypt else s))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def atbash(text: str) -> str:
    """Reverse the alphabet (A<->Z). It has no key at all: pure obscurity."""
    return "".join(
        chr(155 - ord(c)) if c.isascii() and c.isupper()
        else chr(219 - ord(c)) if c.isascii() and c.islower() else c
        for c in text)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def chi_squared(text: str) -> float:
    """Lower = closer to English letter frequencies."""
    letters = [c for c in text.lower() if c in ENGLISH_FREQ]
    if not letters:
        return float("inf")
    counts, n = Counter(letters), len(letters)
    return sum((counts.get(l, 0) - n * f / 100) ** 2 / (n * f / 100) for l, f in ENGLISH_FREQ.items())


def crack_caesar(ciphertext: str) -> list[tuple[int, float, str]]:
    """Try all 25 shifts and rank by English-likeness. Returns [(shift, score, plaintext)]."""
    candidates = [(s, chi_squared(caesar(ciphertext, -s)), caesar(ciphertext, -s)) for s in range(1, 26)]
    return sorted(candidates, key=lambda c: c[1])


def frequency_table(text: str) -> list[tuple[str, int, float]]:
    letters = [c for c in text.lower() if c in ENGLISH_FREQ]
    counts = Counter(letters)
    return [(l, n, 100 * n / len(letters)) for l, n in counts.most_common()] if letters else []


def read_text(args) -> str:
    return args.text if args.text is not None else sys.stdin.read().rstrip("\n")


def main() -> None:
    p = argparse.ArgumentParser(description="Classic ciphers for learning (NOT secure).")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, help_):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("text", nargs="?", help="text (reads stdin if omitted)")
        return sp

    c = add("caesar", "Caesar shift cipher")
    c.add_argument("-k", "--shift", type=int, required=True)
    c.add_argument("-d", "--decrypt", action="store_true")
    v = add("vigenere", "Vigenere cipher")
    v.add_argument("-k", "--key", required=True)
    v.add_argument("-d", "--decrypt", action="store_true")
    add("rot13", "ROT13 (Caesar with shift 13; applying it twice decrypts)")
    add("atbash", "Atbash (reversed alphabet)")
    x = add("xor", "XOR with a repeating key; encrypt outputs hex, use --hex-in to decrypt")
    x.add_argument("-k", "--key", required=True, help="key as text")
    x.add_argument("--hex-in", action="store_true", help="treat input as hex (to decrypt)")
    add("crack-caesar", "brute-force a Caesar ciphertext and rank candidates")
    add("freq", "letter-frequency analysis")
    args = p.parse_args()

    try:
        text = read_text(args)
        if args.cmd == "caesar":
            print(caesar(text, -args.shift if args.decrypt else args.shift))
        elif args.cmd == "vigenere":
            print(vigenere(text, args.key, args.decrypt))
        elif args.cmd == "rot13":
            print(caesar(text, 13))
        elif args.cmd == "atbash":
            print(atbash(text))
        elif args.cmd == "xor":
            data = bytes.fromhex(text.replace(" ", "")) if args.hex_in else text.encode()
            result = xor_bytes(data, args.key.encode())
            print(result.decode("utf-8", errors="replace") if args.hex_in else result.hex())
        elif args.cmd == "crack-caesar":
            print("Best guesses (lower score = more English-like):")
            for shift, score, plain in crack_caesar(text)[:5]:
                print(f"  shift {shift:>2}  score {score:8.1f}  {plain[:70]}")
        elif args.cmd == "freq":
            for letter, n, pct in frequency_table(text):
                print(f"{letter}  {n:>4}  {pct:5.1f}%  {'#' * int(pct)}  (English: {ENGLISH_FREQ[letter]}%)")
    except ValueError as exc:
        sys.exit(f"Error: {exc}")


if __name__ == "__main__":
    main()
