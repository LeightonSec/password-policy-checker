"""Shared fixtures for the test suite."""


import pytest


@pytest.fixture
def sample_policy_nist(tmp_path):
    """A NIST-compliant policy configuration file."""
    p = tmp_path / "policy_nist.json"
    p.write_text("""{
        "name": "NIST Compliant",
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
            "allow_unicode": true,
            "allow_hints": false
        }
    }""")
    return p


@pytest.fixture
def sample_policy_strict(tmp_path):
    """A legacy corporate policy that violates several NIST rules."""
    p = tmp_path / "policy_strict.json"
    p.write_text("""{
        "name": "Legacy Corporate",
        "version": "1.0",
        "rules": {
            "min_length": 8,
            "max_length": 16,
            "require_uppercase": true,
            "require_lowercase": true,
            "require_digits": true,
            "require_special": true,
            "expiry_days": 90,
            "check_hibp": false,
            "check_common_passwords": false,
            "allow_unicode": false,
            "allow_hints": true
        }
    }""")
    return p


@pytest.fixture
def sample_passwords_file(tmp_path):
    """A small batch of test passwords."""
    p = tmp_path / "passwords.txt"
    p.write_text("\n".join([
        "# Test password list",
        "correcthorsebatterystaple",
        "P@ssw0rd123!",
        "123456",
        "password",
        "Tr0ub4dor&3",
        "aaaaaaaa",
        "qwerty123",
        "MyL0ng&SecureP@ssphrase2024",
    ]) + "\n")
    return p
