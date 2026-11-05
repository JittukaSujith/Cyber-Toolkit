# Password Strength Checker

**Type:** GUI + CLI (Tkinter)  |  **Category:** Defensive

## What it does
Scores a password using an entropy estimate, a common-password list, leetspeak normalisation and pattern detection, then estimates offline crack time. The CLI can also run a Have I Been Pwned breach check using k-anonymity.

## What you will learn
- Entropy = length x log2(pool size), and why length beats complexity
- Why 'P@ssw0rd!' is weak: attackers use wordlists plus mutation rules
- k-anonymity: checking breaches without revealing the password

## Usage
```bash
cd password_strength_checker
python password_checker.py            # GUI
python password_checker.py --cli --hibp  # terminal, hidden input, breach check
```

## Example output (illustrative)
```text
Strength : Very weak (0/4)
Entropy  : ~10 bits
Crack est: instantly at 1e+10 guesses/sec (offline, fast hash)
  - This is a very common password (even with 'leet' substitutions).
```

## Try it yourself
- Compare 'Tr0ub4dor&3' with 'correct horse battery staple'. Which does the tool prefer, and is it right?
- Add a check for dates or keyboard patterns of your own.
- Add the GUI breach check button.

## Limitations
Entropy estimates assume random characters, so dictionary passphrases are over-estimated. Real tools such as zxcvbn model dictionaries and patterns more fully.
