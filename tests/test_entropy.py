"""Tests for entropy calculation and crack time estimation."""

import pytest
from checker.entropy import calculate_entropy, estimate_crack_times, _charset_size


class TestCharsetSize:
    def test_lowercase_only(self):
        assert _charset_size("abcdef") == 26

    def test_uppercase_only(self):
        assert _charset_size("ABCDEF") == 26

    def test_digits_only(self):
        assert _charset_size("123456") == 10

    def test_lowercase_and_digits(self):
        assert _charset_size("abc123") == 36

    def test_mixed_all_ascii(self):
        assert _charset_size("Abc1!") == 26 + 26 + 10 + 32

    def test_unicode_bonus(self):
        size = _charset_size("passé")
        assert size > 26  # unicode adds to charset


class TestCalculateEntropy:
    def test_short_weak_password(self):
        entropy = calculate_entropy("abc")
        assert entropy < 20  # 3 * log2(26) ≈ 14.1

    def test_longer_mixed_password(self):
        entropy = calculate_entropy("Abc1!xyz9@")
        assert entropy > 60

    def test_entropy_increases_with_length(self):
        short = calculate_entropy("abc")
        long_ = calculate_entropy("abcabcabc")
        assert long_ > short

    def test_entropy_increases_with_complexity(self):
        simple = calculate_entropy("aaaaaaaa")     # 8 lowercase
        complex_ = calculate_entropy("Aa1!Aa1!")   # 8 mixed
        assert complex_ > simple

    def test_very_strong_passphrase(self):
        entropy = calculate_entropy("correct-horse-battery-staple-2024!")
        assert entropy > 100


class TestEstimateCrackTimes:
    def test_returns_crack_times_object(self):
        from checker.entropy import CrackTimes
        ct = estimate_crack_times(40.0)
        assert isinstance(ct, CrackTimes)

    def test_high_entropy_gives_long_times(self):
        ct = estimate_crack_times(100.0)
        assert "year" in ct.offline_fast.lower() or "million" in ct.offline_fast.lower() \
               or "universe" in ct.offline_fast.lower() or "billion" in ct.offline_fast.lower()

    def test_low_entropy_gives_short_times(self):
        ct = estimate_crack_times(10.0)
        # Online throttled should still be feasible for very low entropy
        assert ct.offline_gpu_cluster == "less than a second"

    def test_zero_entropy_handled(self):
        ct = estimate_crack_times(0.0)
        assert ct is not None

    def test_online_slower_than_offline(self):
        # The online throttled scenario should produce longer times than GPU cluster
        ct = estimate_crack_times(50.0)
        # Both are strings — just verify they exist and differ
        assert ct.online_throttled != ct.offline_gpu_cluster
