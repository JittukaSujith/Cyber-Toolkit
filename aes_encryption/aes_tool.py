#!/usr/bin/env python3
"""
AES-256-GCM Encryption Tool (GUI by default; CLI subcommands available)

SECURITY IDEAS:
  * AES is a block cipher; the MODE matters. We use GCM, an AEAD mode that provides
    confidentiality AND integrity: tampering or a wrong password makes decryption FAIL
    loudly instead of returning garbage. (ECB leaks patterns; unauthenticated CBC is
    malleable.)
  * Humans have passwords, AES needs a 256-bit key. A KDF bridges the gap. We use scrypt,
    which is deliberately slow and memory-hard to make password guessing expensive.
  * A random SALT makes the same password yield a different key every time (defeats
    precomputed tables). A random 96-bit NONCE must NEVER repeat for the same key.
  * Salt and nonce are not secret; we store them in the file header. The header is
    passed as "associated data" so it is authenticated too.
File format:  MAGIC(5) | salt(16) | nonce(12) | ciphertext + 16-byte tag

Requires: cryptography (pip install cryptography)
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import os
import pathlib
import sys

MAGIC = b"AESG1"
SALT_LEN, NONCE_LEN = 16, 12
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1  # ~32 MiB of memory per guess


def derive_key(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(password.encode())


def encrypt_bytes(password: str, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not password:
        raise ValueError("password must not be empty")
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)  # os.urandom = OS CSPRNG
    header = MAGIC + salt + nonce
    ciphertext = AESGCM(derive_key(password, salt)).encrypt(nonce, plaintext, header)
    return header + ciphertext


def decrypt_bytes(password: str, blob: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN
    if len(blob) < header_len + 16 or not blob.startswith(MAGIC):
        raise ValueError("not a valid encrypted blob (bad header)")
    header = blob[:header_len]
    salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
    nonce = blob[len(MAGIC) + SALT_LEN:header_len]
    try:
        return AESGCM(derive_key(password, salt)).decrypt(nonce, blob[header_len:], header)
    except InvalidTag:
        raise ValueError("decryption failed: wrong password or the data was modified")


def encrypt_text(password: str, text: str) -> str:
    return base64.b64encode(encrypt_bytes(password, text.encode())).decode()


def decrypt_text(password: str, token: str) -> str:
    try:
        blob = base64.b64decode(token.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("input is not valid base64")
    try:
        return decrypt_bytes(password, blob).decode()
    except UnicodeDecodeError:
        raise ValueError("decrypted data is not valid UTF-8 text")


def _check_file(path: str) -> pathlib.Path:
    p = pathlib.Path(path)
    if not p.is_file():
        raise ValueError(f"'{path}' is not a file")
    return p


def encrypt_file(password: str, src: str, dst: str | None = None) -> str:
    src_p = _check_file(src)
    dst_p = pathlib.Path(dst) if dst else src_p.with_name(src_p.name + ".enc")
    dst_p.write_bytes(encrypt_bytes(password, src_p.read_bytes()))
    return str(dst_p)


def decrypt_file(password: str, src: str, dst: str | None = None) -> str:
    src_p = _check_file(src)
    dst_p = pathlib.Path(dst) if dst else src_p.with_name(src_p.name[:-4] if src_p.suffix == ".enc" else src_p.name + ".dec")
    dst_p.write_bytes(decrypt_bytes(password, src_p.read_bytes()))
    return str(dst_p)


def ask_password(confirm: bool) -> str:
    pw = getpass.getpass("Password: ")
    if confirm and pw != getpass.getpass("Confirm password: "):
        raise ValueError("passwords do not match")
    return pw


def run_gui() -> None:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        sys.exit("tkinter is not available. Install python3-tk or use the CLI (see --help).")

    root = tk.Tk()
    root.title("AES-256-GCM Tool")
    root.geometry("640x520")
    frame = ttk.Frame(root, padding=12)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text="Password (never stored):").pack(anchor="w")
    pw_var = tk.StringVar()
    ttk.Entry(frame, textvariable=pw_var, show="*", width=40).pack(anchor="w", pady=4)
    ttk.Label(frame, text="Input text (plaintext, or base64 to decrypt):").pack(anchor="w")
    inp = tk.Text(frame, height=8)
    inp.pack(fill="x", pady=4)
    ttk.Label(frame, text="Output:").pack(anchor="w")
    out = tk.Text(frame, height=8)
    out.pack(fill="x", pady=4)

    def run(action):
        try:
            result = action(pw_var.get(), inp.get("1.0", "end").strip())
        except ValueError as exc:
            messagebox.showerror("Error", str(exc))
            return
        out.delete("1.0", "end")
        out.insert("end", result)

    def file_action(action, title):
        path = filedialog.askopenfilename(title=title)
        if not path:
            return
        try:
            messagebox.showinfo("Done", f"Saved: {action(pw_var.get(), path)}")
        except (ValueError, OSError) as exc:
            messagebox.showerror("Error", str(exc))

    buttons = ttk.Frame(frame)
    buttons.pack(anchor="w", pady=6)
    for label, cmd in (("Encrypt text", lambda: run(encrypt_text)), ("Decrypt text", lambda: run(decrypt_text)),
                       ("Encrypt file...", lambda: file_action(encrypt_file, "File to encrypt")),
                       ("Decrypt file...", lambda: file_action(decrypt_file, "File to decrypt"))):
        ttk.Button(buttons, text=label, command=cmd).pack(side="left", padx=4)
    root.mainloop()


def main() -> None:
    p = argparse.ArgumentParser(description="AES-256-GCM encryption. Run with no arguments for the GUI.")
    sub = p.add_subparsers(dest="cmd")
    for name in ("encrypt-text", "decrypt-text"):
        sub.add_parser(name).add_argument("text")
    for name in ("encrypt-file", "decrypt-file"):
        sp = sub.add_parser(name)
        sp.add_argument("src")
        sp.add_argument("-o", "--output")
    args = p.parse_args()
    if not args.cmd:
        run_gui()
        return
    try:
        pw = ask_password(confirm=args.cmd.startswith("encrypt"))
        if args.cmd == "encrypt-text":
            print(encrypt_text(pw, args.text))
        elif args.cmd == "decrypt-text":
            print(decrypt_text(pw, args.text))
        elif args.cmd == "encrypt-file":
            print("Wrote", encrypt_file(pw, args.src, args.output))
        else:
            print("Wrote", decrypt_file(pw, args.src, args.output))
    except (ValueError, OSError) as exc:
        sys.exit(f"Error: {exc}")


if __name__ == "__main__":
    main()
