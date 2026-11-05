# AES-256-GCM Encryption Tool

**Type:** GUI + CLI  |  **Category:** Crypto

## What it does
Encrypts and decrypts text or files with AES-256-GCM. Keys are derived from your password with scrypt and a random salt; every message gets a random nonce; tampering or a wrong password makes decryption fail.

## What you will learn
- Authenticated encryption (AEAD) vs unauthenticated modes
- Password-based key derivation and why it must be slow
- Salts and nonces, and why a nonce must never repeat
- Using a vetted library instead of rolling your own crypto

## Usage
```bash
cd aes_encryption
pip install cryptography
python aes_tool.py                              # GUI
python aes_tool.py encrypt-text "meet at noon"
python aes_tool.py decrypt-file notes.txt.enc
```

## Example output (illustrative)
```text
$ python aes_tool.py encrypt-text hello
Password: ******
QUVTRzEu...(base64)
```

## Try it yourself
- Flip one byte in an encrypted file and watch decryption refuse it.
- Encrypt the same text twice and compare the outputs (different salt and nonce).
- Add secure deletion of the plaintext or a --stdin mode.

## Limitations
Whole files are loaded into memory (fine for learning, not for multi-GB files). Strength depends on password strength. Review before protecting anything critical.
