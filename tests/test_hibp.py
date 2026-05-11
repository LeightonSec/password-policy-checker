"""Tests for HIBP k-anonymity integration."""

import hashlib
from unittest.mock import MagicMock, patch

from checker.hibp import check_hibp


def _make_hibp_response(password: str, count: int = 5) -> str:
    """Build a fake HIBP response that includes the given password's hash suffix."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    suffix = sha1[5:]
    # Build a response with the target suffix plus some decoys
    lines = [
        "AAAAABBBBBCCCCCDDDDDEEEEE:0",   # padding decoy
        f"{suffix}:{count}",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1",
    ]
    return "\r\n".join(lines)


def _make_clean_response(password: str) -> str:
    """Build a fake HIBP response that does NOT include the given password."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    sha1[5:]
    # Return a response with different suffixes
    return "AAAAABBBBBCCCCCDDDDDEEEEE:3\r\nFFFFFBBBBBCCCCCDDDDDEEEEE:7"


class TestCheckHIBP:
    def test_breached_password_detected(self):
        password = "password"
        fake_body = _make_hibp_response(password, count=3_500_000)
        mock_response = MagicMock()
        mock_response.text = fake_body
        mock_response.raise_for_status = MagicMock()

        with patch("checker.hibp.httpx.get", return_value=mock_response):
            is_breached, count, error = check_hibp(password)

        assert is_breached is True
        assert count == 3_500_000
        assert error is None

    def test_clean_password_not_flagged(self):
        password = "Xk9$mP2@nQ7!vR4#"  # Unlikely to be in breaches
        fake_body = _make_clean_response(password)
        mock_response = MagicMock()
        mock_response.text = fake_body
        mock_response.raise_for_status = MagicMock()

        with patch("checker.hibp.httpx.get", return_value=mock_response):
            is_breached, count, error = check_hibp(password)

        assert is_breached is False
        assert count == 0
        assert error is None

    def test_padding_entry_not_counted_as_breach(self):
        """Add-Padding entries with count=0 must not trigger a breach flag."""
        password = "test_padding_check"
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        suffix = sha1[5:]
        # Return the correct suffix but with count=0 (padding decoy)
        fake_body = f"{suffix}:0\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:5"

        mock_response = MagicMock()
        mock_response.text = fake_body
        mock_response.raise_for_status = MagicMock()

        with patch("checker.hibp.httpx.get", return_value=mock_response):
            is_breached, count, error = check_hibp(password)

        assert is_breached is False
        assert count == 0

    def test_timeout_returns_error(self):
        import httpx
        with patch("checker.hibp.httpx.get", side_effect=httpx.TimeoutException("timeout")):
            is_breached, count, error = check_hibp("anypassword")

        assert is_breached is False
        assert error is not None
        assert "timeout" in error.lower()

    def test_http_error_returns_error(self):
        import httpx
        mock_response = MagicMock()
        mock_response.status_code = 429
        with patch(
            "checker.hibp.httpx.get",
            side_effect=httpx.HTTPStatusError("rate limited", request=MagicMock(), response=mock_response),
        ):
            is_breached, count, error = check_hibp("anypassword")

        assert is_breached is False
        assert error is not None

    def test_only_prefix_sent_to_api(self):
        """Verify that only the 5-char prefix is included in the API URL, never the full hash."""
        password = "testpassword"
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        expected_prefix = sha1[:5]

        mock_response = MagicMock()
        mock_response.text = ""
        mock_response.raise_for_status = MagicMock()

        with patch("checker.hibp.httpx.get", return_value=mock_response) as mock_get:
            check_hibp(password)

        call_url = mock_get.call_args[0][0]
        assert expected_prefix in call_url
        # Full hash must not appear in the URL
        assert sha1 not in call_url
        assert sha1[5:] not in call_url
