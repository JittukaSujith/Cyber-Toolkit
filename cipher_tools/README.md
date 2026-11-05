# Classic Cipher Toolkit

**Type:** CLI  |  **Category:** Crypto / Educational

## What it does
Caesar, ROT13, Vigenere, Atbash and repeating-key XOR, plus an automatic Caesar cracker (chi-squared against English letter frequencies) and a letter-frequency analyser.

## What you will learn
- Why historical ciphers are broken
- Kerckhoffs's principle
- Brute force on small key spaces and frequency analysis
- XOR as the core of stream ciphers (and key reuse problems)

## Usage
```bash
cd cipher_tools
python cipher_tools.py caesar -k 7 "Hello World"
python cipher_tools.py crack-caesar "Aol xbpjr iyvdu mve"
python cipher_tools.py vigenere -k LEMON "Attack at dawn"
python cipher_tools.py xor -k key "secret"
```

## Example output (illustrative)
```text
Best guesses (lower score = more English-like):
  shift  7  score    110.4  The quick brown fox jumps over the lazy dog
```

## Try it yourself
- Encrypt a paragraph with Vigenere and try to break it by hand (Kasiski examination).
- Add a monoalphabetic substitution cracker using hill climbing.

## Limitations
For education only. Short ciphertexts can fool frequency analysis. Use AES (see ../aes_encryption) for real data.
