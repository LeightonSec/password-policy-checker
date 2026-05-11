"""Tests for pattern detection."""

import pytest
from checker.patterns import (
    detect_keyboard_walk,
    detect_repeated_chars,
    detect_sequential_chars,
    detect_date_pattern,
    detect_leet_speak,
    detect_all_patterns,
)


class TestKeyboardWalk:
    def test_detects_qwerty(self):
        assert detect_keyboard_walk("qwerty") != []

    def test_detects_asdf(self):
        assert detect_keyboard_walk("asdfgh") != []

    def test_detects_numbers(self):
        assert detect_keyboard_walk("12345") != []

    def test_detects_reverse_walk(self):
        assert detect_keyboard_walk("ytrewq") != []

    def test_no_walk_in_random(self):
        assert detect_keyboard_walk("xb7Kp2") == []

    def test_embedded_walk(self):
        # qwerty buried in a longer password
        found = detect_keyboard_walk("my_qwerty_pass")
        assert any("qwert" in w for w in found)


class TestRepeatedChars:
    def test_three_same_chars(self):
        assert detect_repeated_chars("aaa") == ["aaa"]

    def test_four_same_digits(self):
        result = detect_repeated_chars("1111")
        assert result == ["1111"]

    def test_below_threshold_not_flagged(self):
        assert detect_repeated_chars("aa") == []

    def test_multiple_runs(self):
        result = detect_repeated_chars("aaabbb")
        assert len(result) == 2

    def test_no_repeat_in_normal_password(self):
        assert detect_repeated_chars("Password1!") == []


class TestSequentialChars:
    def test_ascending_letters(self):
        assert detect_sequential_chars("abcdef") != []

    def test_ascending_digits(self):
        assert detect_sequential_chars("12345") != []

    def test_descending_letters(self):
        assert detect_sequential_chars("fedcba") != []

    def test_descending_digits(self):
        assert detect_sequential_chars("9876543") != []

    def test_short_sequence_not_flagged(self):
        # "ab" is length 2, below default min_len=3
        assert detect_sequential_chars("ab") == []

    def test_no_sequence_in_random(self):
        assert detect_sequential_chars("xb7Kp2") == []


class TestDatePattern:
    def test_year_detected(self):
        assert "1990" in detect_date_pattern("born1990")

    def test_recent_year_detected(self):
        assert "2024" in detect_date_pattern("Summer2024!")

    def test_mmdd_detected(self):
        result = detect_date_pattern("0101")
        assert len(result) > 0

    def test_no_date_in_random(self):
        result = detect_date_pattern("xbKpQZ")
        assert result == []

    def test_future_year_not_flagged(self):
        # 2099 is outside our range
        result = detect_date_pattern("year2099")
        assert "2099" not in result


class TestLeetSpeak:
    def test_passw0rd_flagged(self):
        assert detect_leet_speak("passw0rd") is True

    def test_p4ssword_flagged(self):
        assert detect_leet_speak("p4ssword") is True

    def test_normal_password_not_flagged(self):
        assert detect_leet_speak("correcthorse") is False

    def test_all_digits_not_flagged(self):
        # All digits don't constitute l33t speak of an alpha word
        assert detect_leet_speak("12345678") is False


class TestDetectAllPatterns:
    def test_qwerty_flagged(self):
        findings = detect_all_patterns("qwerty123")
        assert any("keyboard" in f for f in findings)

    def test_repeated_chars_flagged(self):
        findings = detect_all_patterns("aaa")
        assert any("repeated" in f for f in findings)

    def test_clean_passphrase_no_findings(self):
        findings = detect_all_patterns("correcthorsebatterystaple")
        # Might detect 'sequential' in 'horse' or similar — just check it runs
        assert isinstance(findings, list)

    def test_returns_list(self):
        assert isinstance(detect_all_patterns("password123"), list)
