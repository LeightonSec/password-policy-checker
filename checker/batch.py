"""Batch password evaluation and aggregate reporting."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .evaluator import evaluate_password, PasswordEvaluation
from .policy import PolicyConfig


@dataclass
class BatchResult:
    total: int
    evaluated: int
    errors: int

    # Score distribution buckets
    very_weak: int = 0
    weak: int = 0
    fair: int = 0
    good: int = 0
    strong: int = 0
    very_strong: int = 0

    # Threat stats
    common_count: int = 0
    breached_count: int = 0
    hibp_checked: bool = True

    # Aggregate metrics
    avg_score: float = 0.0
    avg_length: float = 0.0
    avg_entropy: float = 0.0

    # Policy compliance (if policy provided)
    policy_pass: int = 0
    policy_fail: int = 0
    policy_name: Optional[str] = None

    # Top pattern findings
    pattern_hits: dict[str, int] = field(default_factory=dict)

    # Lengths histogram (binned)
    length_distribution: dict[str, int] = field(default_factory=dict)


def _passes_policy(result: PasswordEvaluation, policy: PolicyConfig) -> bool:
    """Check if a password evaluation satisfies a policy configuration."""
    if result.password_length < policy.min_length:
        return False
    if result.password_length > policy.max_length:
        return False
    if policy.require_uppercase and not result.has_uppercase:
        return False
    if policy.require_lowercase and not result.has_lowercase:
        return False
    if policy.require_digits and not result.has_digits:
        return False
    if policy.require_special and not result.has_special:
        return False
    if policy.min_entropy_bits > 0 and result.entropy_bits < policy.min_entropy_bits:
        return False
    if policy.check_common_passwords and result.is_common:
        return False
    if result.entropy_bits < 1:
        return False
    return True


def _length_bin(length: int) -> str:
    if length < 8:
        return "< 8"
    if length <= 11:
        return "8–11"
    if length <= 14:
        return "12–14"
    if length <= 19:
        return "15–19"
    return "20+"


def evaluate_batch(
    path: Path,
    check_hibp_api: bool = False,   # Default off for batch — too slow / noisy
    policy: Optional[PolicyConfig] = None,
    progress_callback=None,
) -> BatchResult:
    """
    Evaluate all passwords in a file (one per line) and return aggregate stats.

    Lines starting with '#' are treated as comments and skipped.
    Empty lines are skipped.
    HIBP checks are disabled by default in batch mode to avoid API rate limits.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"Cannot read password file: {exc}") from exc

    passwords = [
        line.strip()
        for line in lines
        if line.strip() and not line.startswith("#")
    ]

    result = BatchResult(
        total=len(passwords),
        evaluated=0,
        errors=0,
        hibp_checked=check_hibp_api,
        policy_name=policy.name if policy else None,
    )

    score_sum = 0.0
    length_sum = 0.0
    entropy_sum = 0.0

    for i, pw in enumerate(passwords):
        if progress_callback:
            progress_callback(i + 1, len(passwords))
        try:
            evaluation = evaluate_password(pw, check_hibp_api=check_hibp_api)
        except Exception:
            result.errors += 1
            continue

        result.evaluated += 1
        score_sum += evaluation.score
        length_sum += evaluation.password_length
        entropy_sum += evaluation.entropy_bits

        rating = evaluation.rating
        if rating == "Very Weak":
            result.very_weak += 1
        elif rating == "Weak":
            result.weak += 1
        elif rating == "Fair":
            result.fair += 1
        elif rating == "Good":
            result.good += 1
        elif rating == "Strong":
            result.strong += 1
        elif rating == "Very Strong":
            result.very_strong += 1

        if evaluation.is_common:
            result.common_count += 1
        if evaluation.is_breached:
            result.breached_count += 1

        for pattern in evaluation.patterns:
            # Extract the pattern type prefix (e.g. "keyboard walk")
            pattern_type = pattern.split(":")[0].strip()
            result.pattern_hits[pattern_type] = result.pattern_hits.get(pattern_type, 0) + 1

        bin_key = _length_bin(evaluation.password_length)
        result.length_distribution[bin_key] = result.length_distribution.get(bin_key, 0) + 1

        if policy:
            if _passes_policy(evaluation, policy):
                result.policy_pass += 1
            else:
                result.policy_fail += 1

    if result.evaluated > 0:
        result.avg_score = round(score_sum / result.evaluated, 1)
        result.avg_length = round(length_sum / result.evaluated, 1)
        result.avg_entropy = round(entropy_sum / result.evaluated, 1)

    return result
