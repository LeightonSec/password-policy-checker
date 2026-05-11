# password-policy-checker

A Python CLI tool for evaluating passwords and organisational password policies against **NIST SP 800-63B**, **NCSC Password Guidance**, and common security best practices.

[![CI](https://github.com/LeightonSec/password-policy-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/LeightonSec/password-policy-checker/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Why this matters

Weak and reused passwords remain the leading cause of breaches — the 2024 Verizon Data Breach Investigations Report found credentials were involved in over 77% of web application attacks. Yet most corporate password policies still mandate complexity rules (uppercase, digits, special characters) that NIST research shows drive predictable workarounds like `Password1!` rather than genuine security. This tool enforces the evidence-based approach: checking passwords against real breach databases and encouraging length over complexity, directly implementing the controls organisations should already have.

---

## Features

| Feature | Details |
|---|---|
| **Single password evaluation** | Length, entropy, character composition, crack time estimation |
| **Breach database check** | HaveIBeenPwned API via k-anonymity (SHA-1 prefix only — full password never transmitted) |
| **Common password detection** | Offline check against curated common-password list |
| **Pattern detection** | Keyboard walks, repeated chars, sequential sequences, date patterns, l33t speak |
| **Policy evaluation** | JSON policy file evaluated against 12 NIST SP 800-63B rules with compliance score |
| **Batch mode** | Aggregate statistics across a password file with optional policy compliance report |
| **Flexible output** | Rich terminal (colour-coded), JSON export, Markdown report export |

---

## Installation

```bash
git clone https://github.com/LeightonSec/password-policy-checker.git
cd password-policy-checker
pip install -e .
```

Or install with dev/test dependencies:

```bash
pip install -r requirements-dev.txt
pip install -e .
```

---

## Quick Start

### Evaluate a password (secure prompt — never stored or logged)

```bash
password-policy-checker check
# Enter password to evaluate: [hidden input]
```

### Evaluate a password against a policy

```bash
password-policy-checker check --policy examples/policy_nist_compliant.json
```

### Export results

```bash
password-policy-checker check --output json --export report.json
password-policy-checker check --output markdown --export report.md
```

### Skip the HIBP API check

```bash
password-policy-checker check --no-hibp
```

---

## Policy Evaluation

Evaluate an organisational password policy against NIST SP 800-63B:

```bash
password-policy-checker policy examples/policy_corporate_strict.json
```

This checks 12 NIST rules and produces a compliance score (0–100). Exit code `2` indicates critical violations.

### Policy JSON format

```json
{
  "name": "My Organisation Policy",
  "version": "1.0",
  "rules": {
    "min_length": 15,
    "max_length": 128,
    "require_uppercase": false,
    "require_lowercase": false,
    "require_digits": false,
    "require_special": false,
    "expiry_days": 0,
    "check_hibp": true,
    "check_common_passwords": true,
    "min_entropy_bits": 40,
    "allow_unicode": true,
    "allow_hints": false
  }
}
```

See `examples/` for ready-to-use NIST-compliant and legacy-corporate policy examples.

---

## Batch Mode

Evaluate a file of passwords and generate aggregate statistics:

```bash
password-policy-checker batch examples/passwords_sample.txt
password-policy-checker batch passwords.txt --policy examples/policy_nist_compliant.json
password-policy-checker batch passwords.txt --output markdown --export batch-report.md
```

> **Security note:** Plaintext password files are sensitive data. Use batch mode only with test/sample data, never production credentials.

HIBP breach checking is disabled by default in batch mode to avoid API rate limiting. Enable explicitly:

```bash
password-policy-checker batch passwords.txt --hibp
```

---

## NIST SP 800-63B Compliance Rules Checked

| Rule ID | Description | Severity |
|---|---|---|
| NIST-001 | Minimum length ≥ 8 characters | Critical |
| NIST-002 | Minimum length ≥ 15 (recommended) | Warning |
| NIST-003 | Maximum length allows ≥ 64 characters | Warning |
| NIST-004 | No mandatory uppercase requirement | Warning |
| NIST-005 | No mandatory lowercase requirement | Warning |
| NIST-006 | No mandatory digit requirement | Warning |
| NIST-007 | No mandatory special character requirement | Warning |
| NIST-008 | No mandatory periodic expiry | Warning |
| NIST-009 | Breach database check enabled | Warning |
| NIST-010 | Common password check enabled | Warning |
| NIST-011 | Password hints disabled | Warning |
| NIST-012 | Unicode characters permitted | Info |

### Key NIST SP 800-63B guidance implemented

**What NIST recommends:**
- Minimum 8 characters; 15+ strongly recommended
- Allow up to at least 64 characters
- Accept all printable ASCII and Unicode
- Check against breached password databases (see [HIBP](https://haveibeenpwned.com))
- Check against commonly used password lists

**What NIST explicitly discourages:**
- Mandatory complexity rules (uppercase, lowercase, digits, specials) — users respond with predictable patterns (`Password1!`) that meet the rule but provide no extra security
- Mandatory periodic rotation — frequent rotation leads to weak, predictable passwords (append a number and increment)
- Password hints — hints reduce the effective entropy of the secret

---

## Security Design

### k-Anonymity for HIBP

Passwords are **never** transmitted to the HIBP API. The check works as follows:

1. Compute the SHA-1 hash of the password locally
2. Send only the **first 5 hex characters** (the prefix) to `api.pwnedpasswords.com/range/{prefix}`
3. Receive a list of ~1000 hash suffixes that share that prefix
4. Compare the remaining suffix **locally** — no network transmission

This is the [k-anonymity model](https://haveibeenpwned.com/API/v3#PwnedPasswords) designed by Troy Hunt. The `Add-Padding: true` header is included so all responses are the same size, preventing traffic-analysis attacks.

### Memory handling

Plaintext passwords are:
- Never written to disk
- Never logged
- Cleared from local variables immediately after evaluation (best-effort; Python's garbage collector is non-deterministic)
- Not included in any export output

---

## Extending the Common Password List

The built-in list covers ~600 commonly-seen passwords. For production use, replace or supplement it with a larger list from [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials):

```bash
curl -o checker/data/common_passwords.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
```

---

## Running Tests

```bash
pytest
```

With coverage:

```bash
pytest --cov=checker --cov-report=term-missing
```

---

## Project Structure

```
password-policy-checker/
├── checker/
│   ├── cli.py          # Typer CLI commands (check, policy, batch, version)
│   ├── evaluator.py    # Core password evaluation engine
│   ├── entropy.py      # Shannon entropy and crack time estimation
│   ├── hibp.py         # HaveIBeenPwned k-anonymity API integration
│   ├── patterns.py     # Keyboard walks, repeats, sequences, l33t speak
│   ├── policy.py       # Policy loading and NIST SP 800-63B evaluation
│   ├── batch.py        # Aggregate batch evaluation
│   ├── reporter.py     # Terminal (rich), JSON, and Markdown output
│   └── data/
│       └── common_passwords.txt
├── tests/
│   ├── test_entropy.py
│   ├── test_patterns.py
│   ├── test_hibp.py
│   ├── test_evaluator.py
│   ├── test_policy.py
│   └── test_batch.py
├── examples/
│   ├── policy_nist_compliant.json
│   ├── policy_corporate_strict.json
│   └── passwords_sample.txt
├── .github/workflows/ci.yml
└── pyproject.toml
```

---

## References

- [NIST SP 800-63B — Digital Identity Guidelines: Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [NCSC — Password administration for system owners](https://www.ncsc.gov.uk/collection/passwords)
- [HaveIBeenPwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [SecLists — Common Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

## Licence

MIT — see [LICENSE](LICENSE).
