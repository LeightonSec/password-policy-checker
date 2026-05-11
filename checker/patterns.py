"""Pattern detection: keyboard walks, repeats, sequences, l33t speak."""

from __future__ import annotations

# QWERTY keyboard adjacency rows (horizontal, left→right)
_KEYBOARD_ROWS = [
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    # Diagonal columns (top to bottom, common walk patterns)
    "qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm",
    # Numpad rows
    "789", "456", "123",
]

# Build a flat set of all 3+ length sequences (forward and backward)
def _build_sequences(min_len: int = 3) -> set[str]:
    seqs: set[str] = set()
    for row in _KEYBOARD_ROWS:
        for length in range(min_len, len(row) + 1):
            for start in range(len(row) - length + 1):
                fragment = row[start:start + length]
                seqs.add(fragment)
                seqs.add(fragment[::-1])
    return seqs


_KEYBOARD_SEQUENCES = _build_sequences()

# Common l33t substitution map (l33t → plain)
_LEET_MAP: dict[str, str] = {
    "4": "a", "@": "a", "3": "e", "1": "i", "!": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "+": "t",
    "6": "g", "9": "g", "8": "b", "2": "z",
}


def _deleet(password: str) -> str:
    """Reverse l33t speak substitutions to reveal base word."""
    return "".join(_LEET_MAP.get(c, c) for c in password.lower())


def detect_keyboard_walk(password: str) -> list[str]:
    """Find keyboard walk sequences of 3+ chars."""
    found: list[str] = []
    lower = password.lower()
    for seq in _KEYBOARD_SEQUENCES:
        if len(seq) >= 3 and seq in lower:
            found.append(seq)
    # Return longest non-overlapping matches to avoid noise
    found.sort(key=len, reverse=True)
    deduplicated: list[str] = []
    covered = set()
    for seq in found:
        pos = lower.find(seq)
        span = set(range(pos, pos + len(seq)))
        if not span & covered:
            deduplicated.append(seq)
            covered |= span
    return deduplicated


def detect_repeated_chars(password: str, threshold: int = 3) -> list[str]:
    """Detect runs of the same character (e.g. 'aaa', '111')."""
    found: list[str] = []
    i = 0
    while i < len(password):
        j = i + 1
        while j < len(password) and password[j] == password[i]:
            j += 1
        run_length = j - i
        if run_length >= threshold:
            found.append(password[i] * run_length)
        i = j
    return found


def detect_sequential_chars(password: str, min_len: int = 3) -> list[str]:
    """Detect ascending or descending character sequences (e.g. 'abc', '987')."""
    found: list[str] = []
    lower = password.lower()
    i = 0
    while i < len(lower) - min_len + 1:
        # Try ascending
        j = i + 1
        while j < len(lower) and ord(lower[j]) == ord(lower[j - 1]) + 1:
            j += 1
        if j - i >= min_len:
            found.append(password[i:j])
            i = j
            continue
        # Try descending
        j = i + 1
        while j < len(lower) and ord(lower[j]) == ord(lower[j - 1]) - 1:
            j += 1
        if j - i >= min_len:
            found.append(password[i:j])
            i = j
            continue
        i += 1
    return found


def detect_date_pattern(password: str) -> list[str]:
    """Detect obvious date patterns (years, MMDD, DDMM, YYYYMMDD)."""
    import re
    found: list[str] = []
    # 4-digit years in plausible range
    for m in re.finditer(r"(19[0-9]{2}|20[0-2][0-9])", password):
        found.append(m.group())
    # MMDD or DDMM patterns (0101 through 1231 excluding years)
    for m in re.finditer(r"(?<!\d)(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])(?!\d)", password):
        found.append(m.group())
    return list(dict.fromkeys(found))  # deduplicate, preserve order


def detect_leet_speak(password: str) -> bool:
    """Return True if the password appears to use l33t speak substitutions."""
    leet_chars = set(_LEET_MAP.keys())
    leet_count = sum(1 for c in password if c in leet_chars)
    # Flag if ≥20% of characters are l33t substitutions and the deobfuscated
    # string contains only alpha characters (implies a word base)
    if leet_count == 0:
        return False
    # Pure digit/symbol strings (no real alpha chars) are not l33t speak —
    # they have no underlying word being obscured.
    if not any(c.isalpha() for c in password):
        return False
    ratio = leet_count / len(password)
    deobfuscated = _deleet(password)
    # ≥10% substitution rate + deobfuscated form is a plain word = l33t speak
    looks_like_word = ratio >= 0.1 and deobfuscated.replace(" ", "").isalpha()
    return looks_like_word


def detect_all_patterns(password: str) -> list[str]:
    """Run all pattern checks and return a list of human-readable findings."""
    findings: list[str] = []

    walks = detect_keyboard_walk(password)
    if walks:
        findings.append(f"keyboard walk: '{walks[0]}'")

    repeats = detect_repeated_chars(password)
    if repeats:
        findings.append(f"repeated characters: '{repeats[0]}'")

    seqs = detect_sequential_chars(password)
    if seqs:
        findings.append(f"sequential characters: '{seqs[0]}'")

    dates = detect_date_pattern(password)
    if dates:
        findings.append(f"date pattern: '{dates[0]}'")

    if detect_leet_speak(password):
        findings.append("l33t speak substitutions detected")

    return findings
