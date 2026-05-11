"""Core password evaluation engine."""

from __future__ import annotations

import importlib.resources
from dataclasses import dataclass, field
from typing import Optional

from .entropy import calculate_entropy, estimate_crack_times, CrackTimes
from .patterns import detect_all_patterns
from .hibp import check_hibp


@dataclass
class PasswordEvaluation:
    # Input metadata (never store the password itself)
    password_length: int
    masked: str                        # e.g. "p*****d" for display

    # Character composition
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_special: bool
    has_unicode: bool
    charset_size: int
    char_types: int                    # distinct character categories present

    # Entropy & crack time
    entropy_bits: float
    crack_times: CrackTimes

    # Threat intelligence
    is_common: bool
    is_breached: bool
    breach_count: int
    hibp_checked: bool
    hibp_error: Optional[str]

    # Pattern findings
    patterns: list[str]

    # Scoring
    score: int                          # 0–100
    rating: str                         # Very Weak / Weak / Fair / Good / Strong / Very Strong
    recommendations: list[str] = field(default_factory=list)


def _mask(password: str) -> str:
    """Return a display-safe masked version of the password."""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def _load_common_passwords() -> frozenset[str]:
    try:
        ref = importlib.resources.files("checker.data").joinpath("common_passwords.txt")
        text = ref.read_text(encoding="utf-8")
        return frozenset(line.strip().lower() for line in text.splitlines() if line.strip())
    except Exception:
        return frozenset()


_COMMON_PASSWORDS: frozenset[str] = _load_common_passwords()


def _score_password(
    length: int,
    entropy_bits: float,
    char_types: int,
    has_unicode: bool,
    is_common: bool,
    is_breached: bool,
    patterns: list[str],
) -> int:
    score = 0

    # Length contribution (0–30)
    if length >= 20:
        score += 30
    elif length >= 15:
        score += 25
    elif length >= 12:
        score += 20
    elif length >= 10:
        score += 15
    elif length >= 8:
        score += 10
    # < 8 gets nothing

    # Entropy contribution (0–30)
    if entropy_bits >= 80:
        score += 30
    elif entropy_bits >= 60:
        score += 25
    elif entropy_bits >= 45:
        score += 20
    elif entropy_bits >= 36:
        score += 15
    elif entropy_bits >= 28:
        score += 10
    elif entropy_bits >= 20:
        score += 5

    # Character diversity (0–20)
    diversity_pts = [0, 0, 5, 10, 20, 25]
    score += diversity_pts[min(char_types, 5)]
    if has_unicode:
        score += 5

    # Penalties
    if is_common:
        score -= 35
    if is_breached:
        score -= 25
    for _ in patterns:
        score -= 7

    return max(0, min(100, score))


def _rating(score: int) -> str:
    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Fair"
    if score < 75:
        return "Good"
    if score < 90:
        return "Strong"
    return "Very Strong"


def _build_recommendations(
    length: int,
    char_types: int,
    has_uppercase: bool,
    has_lowercase: bool,
    has_digits: bool,
    has_special: bool,
    is_common: bool,
    is_breached: bool,
    patterns: list[str],
    entropy_bits: float,
) -> list[str]:
    recs: list[str] = []

    if is_breached:
        recs.append("This password has appeared in data breaches — change it immediately.")
    if is_common:
        recs.append("This is a commonly used password and will be tried first by attackers.")
    if length < 8:
        recs.append("Increase length to at least 8 characters (NIST SP 800-63B minimum).")
    elif length < 15:
        recs.append("Consider increasing length to 15+ characters (NIST recommended).")
    if patterns:
        recs.append(f"Avoid predictable patterns: {', '.join(patterns[:3])}.")
    if char_types < 2:
        recs.append("Mix character types — letters, digits, and symbols improve entropy.")
    if entropy_bits < 36 and not recs:
        recs.append("Consider a longer passphrase (4+ random words) for easier memorability and higher entropy.")
    if not recs:
        recs.append("Password meets baseline security requirements.")
    return recs


def evaluate_password(password: str, check_hibp_api: bool = True) -> PasswordEvaluation:
    """
    Fully evaluate a password without logging or storing it.

    Args:
        password: The plaintext password to evaluate.
        check_hibp_api: Whether to query the HIBP k-anonymity API.

    Returns:
        PasswordEvaluation dataclass with all findings.
    """
    length = len(password)

    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    specials = set('!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ')
    has_special = any(c in specials for c in password)
    has_unicode = any(ord(c) > 127 for c in password)

    char_types = sum([has_lowercase, has_uppercase, has_digits, has_special, has_unicode])

    charset_size = (
        (26 if has_lowercase else 0)
        + (26 if has_uppercase else 0)
        + (10 if has_digits else 0)
        + (32 if has_special else 0)
        + (128 if has_unicode else 0)
    )

    entropy = calculate_entropy(password)
    crack_times = estimate_crack_times(entropy)
    patterns = detect_all_patterns(password)

    is_common = password.lower() in _COMMON_PASSWORDS

    if check_hibp_api:
        is_breached, breach_count, hibp_error = check_hibp(password)
        hibp_checked = True
    else:
        is_breached, breach_count, hibp_error = False, 0, None
        hibp_checked = False

    score = _score_password(
        length, entropy, char_types, has_unicode,
        is_common, is_breached, patterns,
    )

    recommendations = _build_recommendations(
        length, char_types, has_uppercase, has_lowercase,
        has_digits, has_special, is_common, is_breached,
        patterns, entropy,
    )

    # Wipe sensitive reference before returning
    password = "0" * length
    del password

    return PasswordEvaluation(
        password_length=length,
        masked=_mask("*" * length),   # masked is constructed from length, not password
        has_lowercase=has_lowercase,
        has_uppercase=has_uppercase,
        has_digits=has_digits,
        has_special=has_special,
        has_unicode=has_unicode,
        charset_size=charset_size,
        char_types=char_types,
        entropy_bits=round(entropy, 1),
        crack_times=crack_times,
        is_common=is_common,
        is_breached=is_breached,
        breach_count=breach_count,
        hibp_checked=hibp_checked,
        hibp_error=hibp_error,
        patterns=patterns,
        score=score,
        rating=_rating(score),
        recommendations=recommendations,
    )
