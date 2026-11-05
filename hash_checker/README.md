# Hash Checker

**Type:** GUI + CLI  |  **Category:** Crypto / Defensive

## What it does
Computes MD5, SHA-1, SHA-256, SHA-512, SHA3-256 or BLAKE2b of a file or text and verifies it against an expected hash in constant time. Auto-detects the algorithm from hash length.

## What you will learn
- Integrity vs authenticity
- Why MD5 and SHA-1 are broken for security purposes
- Chunked hashing of large files
- Constant-time comparison

## Usage
```bash
cd hash_checker
python hash_checker.py                      # GUI
python hash_checker.py ubuntu.iso -e <hash>
python hash_checker.py --text hello -a sha256
```

## Example output (illustrative)
```text
sha256: 2cf24dba5fb0a30e...
MATCH: integrity verified.
```

## Try it yourself
- Verify a real download against its published SHA-256.
- Change one byte of a file and watch the hash change completely.
- Add HMAC support.

## Limitations
A matching hash proves integrity only if the expected hash came from a trustworthy, separate channel.
