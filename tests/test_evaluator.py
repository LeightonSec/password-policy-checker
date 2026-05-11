"""Tests for the core password evaluator."""

from unittest.mock import patch

from checker.evaluator import PasswordEvaluation, _rating, _score_password, evaluate_password


class TestEvaluatePassword:
    def test_returns_evaluation_object(self):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_password("TestPassword1!", check_hibp_api=True)
        assert isinstance(result, PasswordEvaluation)

    def test_correct_length_recorded(self):
        pw = "HelloWorld123"
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_password(pw)
        assert result.password_length == len(pw)

    def test_character_types_detected(self):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_password("Abc1!")
        assert result.has_lowercase is True
        assert result.has_uppercase is True
        assert result.has_digits is True
        assert result.has_special is True

    def test_lowercase_only_detected(self):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_password("abcdefgh")
        assert result.has_lowercase is True
        assert result.has_uppercase is False
        assert result.has_digits is False
        assert result.has_special is False

    def test_common_password_flagged(self):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_password("password")
        assert result.is_common is True

    def test_uncommon_password_not_flagged(self):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_password("xK9!mPqR2@nZvT4#")
        assert result.is_common is False

    def test_breached_password_flagged(self):
        with patch("checker.evaluator.check_hibp", return_value=(True, 50000, None)):
            result = evaluate_password("anypassword", check_hibp_api=True)
        assert result.is_breached is True
        assert result.breach_count == 50000

    def test_hibp_skipped_when_disabled(self):
        result = evaluate_password("testpassword", check_hibp_api=False)
        assert result.hibp_checked is False
        assert result.is_breached is False

    def test_hibp_error_captured(self):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, "API timeout")):
            result = evaluate_password("anypassword", check_hibp_api=True)
        assert result.hibp_error == "API timeout"

    def test_entropy_is_positive(self):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_password("Hello123!")
        assert result.entropy_bits > 0

    def test_score_range(self):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_password("testpassword")
        assert 0 <= result.score <= 100

    def test_very_weak_password_low_score(self):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_password("123456")
        assert result.score < 40

    def test_strong_passphrase_high_score(self):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_password("correct-horse-battery-staple-extra-2024!")
        assert result.score >= 60

    def test_recommendations_populated(self):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_password("abc")
        assert len(result.recommendations) > 0

    def test_unicode_detected(self):
        with patch("checker.evaluator.check_hibp", return_value=(False, 0, None)):
            result = evaluate_password("Héllo123!")
        assert result.has_unicode is True

    def test_no_hibp_api_call_when_disabled(self):
        with patch("checker.evaluator.check_hibp") as mock_hibp:
            evaluate_password("anypassword", check_hibp_api=False)
        mock_hibp.assert_not_called()


class TestScoreFunction:
    def test_short_common_breached_scores_zero(self):
        score = _score_password(
            length=6, entropy_bits=15, char_types=1, has_unicode=False,
            is_common=True, is_breached=True, patterns=["keyboard walk", "repeated"],
        )
        assert score == 0

    def test_long_diverse_scores_high(self):
        score = _score_password(
            length=25, entropy_bits=100, char_types=4, has_unicode=False,
            is_common=False, is_breached=False, patterns=[],
        )
        assert score >= 80

    def test_unicode_bonus_applied(self):
        score_no_unicode = _score_password(15, 70, 4, False, False, False, [])
        score_unicode = _score_password(15, 70, 4, True, False, False, [])
        assert score_unicode > score_no_unicode


class TestRating:
    def test_very_weak(self):
        assert _rating(0) == "Very Weak"
        assert _rating(19) == "Very Weak"

    def test_weak(self):
        assert _rating(20) == "Weak"
        assert _rating(39) == "Weak"

    def test_fair(self):
        assert _rating(40) == "Fair"

    def test_good(self):
        assert _rating(60) == "Good"

    def test_strong(self):
        assert _rating(75) == "Strong"

    def test_very_strong(self):
        assert _rating(90) == "Very Strong"
        assert _rating(100) == "Very Strong"
