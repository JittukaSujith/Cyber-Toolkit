#!/usr/bin/env python3
"""
Hash Checker (GUI by default; CLI when you pass arguments)

SECURITY IDEA: A cryptographic hash is a fixed-size fingerprint. Change one bit of the
file and the hash changes completely. Publishers post hashes so you can verify a
download was not corrupted or swapped. Caveats:
  * MD5 and SHA-1 have known collision attacks: fine for accidental-corruption checks,
    NOT for security. Prefer SHA-256 or better.
  * A hash posted on the same compromised site proves nothing. Get it (or better, a
    digital signature) from a separate trusted channel.
  * Compare with hmac.compare_digest (constant time) as a good habit.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import pathlib
import sys

ALGORITHMS = ["md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b"]
LENGTH_TO_ALGO = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}  # hex chars; sha256 vs sha3_256 are ambiguous


def hash_file(path: str | pathlib.Path, algorithm: str = "sha256", chunk_size: int = 1 << 20) -> str:
    """Hash a file in chunks so huge files do not need to fit in memory."""
    if algorithm not in ALGORITHMS:
        raise ValueError(f"unsupported algorithm '{algorithm}'")
    path = pathlib.Path(path)
    if not path.is_file():
        raise ValueError(f"'{path}' is not a file")
    h = hashlib.new(algorithm)
    with path.open("rb") as fh:
        while chunk := fh.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def hash_text(text: str, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, text.encode()).hexdigest()


def clean_expected(expected: str) -> str:
    cleaned = expected.strip().lower().replace(" ", "").replace(":", "")
    if cleaned and any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError("expected hash must be hexadecimal")
    return cleaned


def matches(actual: str, expected: str) -> bool:
    return hmac.compare_digest(actual.lower(), clean_expected(expected))


def run_cli(args) -> int:
    expected = clean_expected(args.expected) if args.expected else None
    algo = args.algo or (LENGTH_TO_ALGO.get(len(expected), "sha256") if expected else "sha256")
    digest = hash_text(args.text, algo) if args.text is not None else hash_file(args.file, algo)
    print(f"{algo}: {digest}")
    if algo in ("md5", "sha1"):
        print("[!] This algorithm is collision-prone; do not rely on it for security decisions.")
    if expected:
        ok = matches(digest, expected)
        print("MATCH: integrity verified." if ok else "MISMATCH: file differs from the expected hash!")
        return 0 if ok else 1
    return 0


def run_gui() -> None:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        sys.exit("tkinter is not available. Install python3-tk or use the CLI (see --help).")

    root = tk.Tk()
    root.title("Hash Checker")
    root.geometry("620x330")
    frame = ttk.Frame(root, padding=14)
    frame.pack(fill="both", expand=True)

    path_var, algo_var, expected_var, result_var = tk.StringVar(), tk.StringVar(value="sha256"), tk.StringVar(), tk.StringVar()
    ttk.Label(frame, text="File:").grid(row=0, column=0, sticky="w")
    ttk.Entry(frame, textvariable=path_var, width=60).grid(row=0, column=1, padx=6, pady=4)
    ttk.Button(frame, text="Browse...", command=lambda: path_var.set(filedialog.askopenfilename() or path_var.get())).grid(row=0, column=2)
    ttk.Label(frame, text="Algorithm:").grid(row=1, column=0, sticky="w")
    ttk.Combobox(frame, textvariable=algo_var, values=ALGORITHMS, state="readonly", width=12).grid(row=1, column=1, sticky="w", padx=6)
    ttk.Label(frame, text="Expected hash\n(optional):").grid(row=2, column=0, sticky="w")
    ttk.Entry(frame, textvariable=expected_var, width=60).grid(row=2, column=1, padx=6, pady=4)
    out = tk.Text(frame, height=6, width=72, state="disabled", wrap="word")
    out.grid(row=4, column=0, columnspan=3, pady=10)
    status = ttk.Label(frame, textvariable=result_var, font=("TkDefaultFont", 11, "bold"))
    status.grid(row=5, column=0, columnspan=3, sticky="w")

    def compute():
        try:
            digest = hash_file(path_var.get(), algo_var.get())
            expected = expected_var.get().strip()
            if expected and algo_var.get() == "sha256" and len(clean_expected(expected)) != 64:
                algo_var.set(LENGTH_TO_ALGO.get(len(clean_expected(expected)), "sha256"))
                digest = hash_file(path_var.get(), algo_var.get())
            text = f"{algo_var.get()}: {digest}"
            if algo_var.get() in ("md5", "sha1"):
                text += "\n[!] Collision-prone algorithm: fine for corruption checks, not security."
            out.config(state="normal"); out.delete("1.0", "end"); out.insert("end", text); out.config(state="disabled")
            if expected:
                ok = matches(digest, expected)
                result_var.set("MATCH - integrity verified" if ok else "MISMATCH - file differs!")
                status.config(foreground="#1e8449" if ok else "#c0392b")
            else:
                result_var.set("")
        except ValueError as exc:
            messagebox.showerror("Input error", str(exc))
        except OSError as exc:
            messagebox.showerror("File error", str(exc))

    ttk.Button(frame, text="Compute / Verify", command=compute).grid(row=3, column=1, sticky="w", padx=6, pady=6)
    root.mainloop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Hash a file/text and optionally verify it. Run with no arguments for the GUI.")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("file", nargs="?", help="file to hash")
    src.add_argument("--text", help="hash this text instead of a file")
    parser.add_argument("-a", "--algo", choices=ALGORITHMS, help="algorithm (auto-detected from --expected length)")
    parser.add_argument("-e", "--expected", help="expected hex digest to compare against")
    args = parser.parse_args()
    if args.file is None and args.text is None:
        run_gui()
        return
    try:
        sys.exit(run_cli(args))
    except (ValueError, OSError) as exc:
        sys.exit(f"Error: {exc}")


if __name__ == "__main__":
    main()
