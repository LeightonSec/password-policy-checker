"""Tests for batch evaluation."""

import pytest
from unittest.mock import patch

from checker.batch import evaluate_batch, _passes_policy, _length_bin
from checker.policy import PolicyConfig


def _make_policy(**kwargs) -> PolicyConfig:
    defaults = dict(
        name="Test",
        version="1.0",
        min_length=8,
        max_length=128,
        require_uppercase=False,
        require_lowercase=False,
        require_digits=False,
        require_special=False,
        max_consecutive_repeated=0,
        expiry_days=0,
        check_hibp=False,
        check_common_passwords=True,
        min_entropy_bits=0.0,
        allow_unicode=True,
        allow_hints=False,
    )
    defaults.update(kwargs)
    return PolicyConfig(**defaults)


class TestLengthBin:
    def test_short(self):
        assert _length_bin(5) == "< 8"

    def test_8_to_11(self):
        assert _length_bin(8) == "8–11"
        assert _length_bin(11) == "8–11"

    def test_12_to_14(self):
        assert _length_bin(12) == "12–14"

    def test_15_to_19(self):
        assert _length_bin(15) == "15–19"

    def test_20_plus(self):
        assert _length_bin(25) == "20+"


class TestPassesPolicy:
    def setup_method(self):
        from unittest.mock import patch
        self._patch = patch("checker.evaluator.check_hibp", return_value=(False, 0, None))
        self._patch.start()

    def teardown_method(self):
        self._patch.stop()

    def test_passes_minimal_policy(self):
        from checker.evaluator import evaluate_password
        result = evaluate_password("LongEnoughPassword1!")
        policy = _make_policy(min_length=8)
        assert _passes_policy(result, policy) is True

    def test_fails_min_length(self):
        from checker.evaluator import evaluate_password
        result = evaluate_password("short")
        policy = _make_policy(min_length=8)
        assert _passes_policy(result, policy) is False

    def test_fails_max_length(self):
        from checker.evaluator import evaluate_password
        long_pw = "a" * 200
        result = evaluate_password(long_pw)
        policy = _make_policy(max_length=64)
        assert _passes_policy(result, policy) is False

    def test_fails_uppercase_requirement(self):
        from checker.evaluator import evaluate_password
        result = evaluate_password("alllowercase1!")
        policy = _make_policy(require_uppercase=True)
        assert _passes_policy(result, policy) is False

    def test_fails_common_password_check(self):
        from checker.evaluator import evaluate_password
        result = evaluate_password("password")
        policy = _make_policy(check_common_passwords=True)
        assert _passes_policy(result, policy) is False


class TestEvaluateBatch:
    def test_basic_batch(self, sample_passwords_file):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_batch(sample_passwords_file, check_hibp_api=False)
        assert result.total > 0
        assert result.evaluated > 0
        assert result.errors == 0

    def test_common_passwords_counted(self, sample_passwords_file):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_batch(sample_passwords_file, check_hibp_api=False)
        # sample file includes '123456' and 'password' — both common
        assert result.common_count >= 2

    def test_avg_score_in_range(self, sample_passwords_file):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_batch(sample_passwords_file, check_hibp_api=False)
        assert 0 <= result.avg_score <= 100

    def test_total_matches_file_contents(self, sample_passwords_file):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_batch(sample_passwords_file, check_hibp_api=False)
        # File has 8 non-comment, non-empty lines
        assert result.total == 8

    def test_policy_compliance_counted(self, sample_passwords_file):
        policy = _make_policy(min_length=15)
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_batch(sample_passwords_file, policy=policy)
        assert result.policy_pass + result.policy_fail == result.evaluated

    def test_missing_file_raises(self, tmp_path):
        from pathlib import Path
        with pytest.raises(ValueError, match="Cannot read"):
            evaluate_batch(Path(tmp_path / "nonexistent.txt"))

    def test_hibp_disabled_by_default(self, sample_passwords_file):
        with patch("checker.evaluator.check_hibp") as mock_hibp:
            evaluate_batch(sample_passwords_file, check_hibp_api=False)
        mock_hibp.assert_not_called()

    def test_distribution_sums_to_evaluated(self, sample_passwords_file):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_batch(sample_passwords_file, check_hibp_api=False)
        total_rated = (
            result.very_weak + result.weak + result.fair
            + result.good + result.strong + result.very_strong
        )
        assert total_rated == result.evaluated
