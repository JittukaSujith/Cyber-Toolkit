# JWT Inspector

**Type:** CLI  |  **Category:** Web / Auth

## What it does
Decodes a JSON Web Token without trusting it, converts time claims, flags risky settings (alg none, missing exp, kid/jku headers, sensitive claims), optionally verifies an HMAC signature and checks a tiny list of famous weak secrets.

## What you will learn
- JWT structure and why base64url is not encryption
- Decoding vs verifying
- alg=none, algorithm confusion, weak HMAC secrets, key-injection headers
- Constant-time signature comparison

## Usage
```bash
cd jwt_inspector
python jwt_inspector.py --demo --secret secret --check-weak-secrets
python jwt_inspector.py eyJhbGciOi... --secret mysecret
```

## Example output (illustrative)
```text
Findings:
  [MEDIUM] No 'exp' claim: token never expires
Weak-secret check: [HIGH] signed with well-known secret 'secret'
```

## Try it yourself
- Decode tokens from your own apps (never paste production tokens into online tools).
- Add RS256 verification with a PEM public key using the cryptography library.

## Limitations
Verifies HMAC algorithms only. The weak-secret list is deliberately tiny and illustrative.
