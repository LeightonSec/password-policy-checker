"""Entropy calculation and crack time estimation."""

import math
from dataclasses import dataclass


@dataclass
class CrackTimes:
    online_throttled: str     # 100 attempts/hour (account lockout scenario)
    online_unthrottled: str   # 1,000/second (no rate limiting)
    offline_slow: str         # bcrypt/Argon2: ~10,000/second/GPU
    offline_fast: str         # MD5/SHA1: ~10 billion/second/GPU
    offline_gpu_cluster: str  # 10 trillion/second (nation-state)


# Guesses per second for each scenario
_RATES = {
    "online_throttled": 100 / 3600,   # 100/hour → per second
    "online_unthrottled": 1_000,
    "offline_slow": 10_000,
    "offline_fast": 10_000_000_000,
    "offline_gpu_cluster": 10_000_000_000_000,
}


def _charset_size(password: str) -> int:
    """Estimate effective character set size from password composition."""
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    specials = set('!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ')
    if any(c in specials for c in password):
        size += 32
    if any(ord(c) > 127 for c in password):
        size += 128  # Conservative Unicode bonus
    return max(size, 1)


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy bits based on character set and length."""
    n = _charset_size(password)
    length = len(password)
    return length * math.log2(n)


def _format_duration(seconds: float) -> str:
    if seconds < 1:
        return "less than a second"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3_600:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 86_400:
        return f"{seconds / 3_600:.1f} hours"
    if seconds < 365.25 * 86_400:
        return f"{seconds / 86_400:.0f} days"
    years = seconds / (365.25 * 86_400)
    if years < 1_000:
        return f"{years:.0f} years"
    if years < 1_000_000:
        return f"{years / 1_000:.0f} thousand years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.0f} million years"
    return "longer than the age of the universe"


def estimate_crack_times(entropy_bits: float) -> CrackTimes:
    """Estimate crack times across different attack scenarios."""
    # Expected guesses = half the keyspace = 2^(entropy - 1)
    half_keyspace = 2 ** max(entropy_bits - 1, 0)

    return CrackTimes(
        online_throttled=_format_duration(half_keyspace / _RATES["online_throttled"]),
        online_unthrottled=_format_duration(half_keyspace / _RATES["online_unthrottled"]),
        offline_slow=_format_duration(half_keyspace / _RATES["offline_slow"]),
        offline_fast=_format_duration(half_keyspace / _RATES["offline_fast"]),
        offline_gpu_cluster=_format_duration(half_keyspace / _RATES["offline_gpu_cluster"]),
    )
