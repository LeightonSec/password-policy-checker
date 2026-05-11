"""HaveIBeenPwned API integration using k-anonymity model.

Only the first 5 characters of the SHA-1 hash are transmitted.
The full password and full hash never leave this machine.
"""

from __future__ import annotations

import hashlib

import httpx

_HIBP_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_TIMEOUT_SECONDS = 8.0


def check_hibp(password: str) -> tuple[bool, int, str | None]:
    """
    Check whether a password appears in the HIBP breach database.

    Uses k-anonymity: only the first 5 hex chars of the SHA-1 hash are sent.
    The response is a list of matching hash suffixes; comparison is local.

    Returns:
        (is_breached, breach_count, error_message)
        error_message is None on success.
    """
    # Compute SHA-1 — store locally only long enough to split
    sha1_upper = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_upper[:5]
    suffix = sha1_upper[5:]
    # Overwrite the full hash immediately — Python can't guarantee memory
    # erasure, but removing the reference reduces the exposure window.
    sha1_upper = "0" * len(sha1_upper)
    del sha1_upper

    try:
        response = httpx.get(
            _HIBP_URL.format(prefix=prefix),
            timeout=_TIMEOUT_SECONDS,
            headers={
                "Add-Padding": "true",   # Prevents traffic-size analysis
                "User-Agent": "password-policy-checker/1.0",
            },
        )
        response.raise_for_status()
    except httpx.TimeoutException:
        return False, 0, "HIBP API timeout"
    except httpx.HTTPStatusError as exc:
        return False, 0, f"HIBP API HTTP {exc.response.status_code}"
    except httpx.RequestError as exc:
        return False, 0, f"HIBP API request failed: {type(exc).__name__}"
    finally:
        # Remove prefix from scope regardless of outcome
        del prefix

    # Scan response lines locally — never log or return the suffix
    is_breached = False
    breach_count = 0
    for line in response.text.splitlines():
        if ":" not in line:
            continue
        response_suffix, count_str = line.split(":", 1)
        if response_suffix.upper() == suffix:
            count = int(count_str)
            if count > 0:   # count=0 entries are Add-Padding decoys
                is_breached = True
                breach_count = count
            break

    del suffix
    return is_breached, breach_count, None
