"""Policy loading and NIST SP 800-63B compliance evaluation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional


PolicySeverity = Literal["critical", "warning", "info", "pass"]


@dataclass
class PolicyRule:
    rule_id: str
    description: str
    severity: PolicySeverity
    nist_reference: str
    recommendation: str


@dataclass
class PolicyConfig:
    name: str
    version: str
    min_length: int
    max_length: int
    require_uppercase: bool
    require_lowercase: bool
    require_digits: bool
    require_special: bool
    max_consecutive_repeated: int       # 0 = no restriction
    expiry_days: int                    # 0 = no expiry (NIST recommended)
    check_hibp: bool
    check_common_passwords: bool
    min_entropy_bits: float
    allow_unicode: bool
    allow_hints: bool                   # should always be False


@dataclass
class PolicyEvaluation:
    policy: PolicyConfig
    compliance_score: int               # 0–100
    nist_compliant: bool                # True only if no critical violations
    violations: list[PolicyRule]
    passes: list[PolicyRule]
    recommendations: list[str]


_NIST_RULES: list[dict] = [
    {
        "id": "NIST-001",
        "check": lambda p: p.min_length >= 8,
        "severity": "critical",
        "description": "Minimum password length must be at least 8 characters",
        "reference": "NIST SP 800-63B §5.1.1",
        "recommendation": f"Set min_length to at least 8. NIST recommends 15+ for memorized secrets.",
        "penalty": 35,
    },
    {
        "id": "NIST-002",
        "check": lambda p: p.min_length >= 15,
        "severity": "warning",
        "description": "Minimum length below NIST recommended 15 characters",
        "reference": "NIST SP 800-63B §5.1.1",
        "recommendation": "Consider raising min_length to 15 or more.",
        "penalty": 10,
    },
    {
        "id": "NIST-003",
        "check": lambda p: p.max_length >= 64,
        "severity": "warning",
        "description": "Maximum length must allow at least 64 characters",
        "reference": "NIST SP 800-63B §5.1.1",
        "recommendation": "Set max_length to at least 64, preferably 128 or unlimited.",
        "penalty": 15,
    },
    {
        "id": "NIST-004",
        "check": lambda p: not p.require_uppercase,
        "severity": "warning",
        "description": "Mandatory uppercase requirement contradicts NIST guidance",
        "reference": "NIST SP 800-63B §5.1.1 (no complexity mandates)",
        "recommendation": "Remove mandatory uppercase. Complexity rules reduce usability without improving security.",
        "penalty": 8,
    },
    {
        "id": "NIST-005",
        "check": lambda p: not p.require_lowercase,
        "severity": "warning",
        "description": "Mandatory lowercase requirement contradicts NIST guidance",
        "reference": "NIST SP 800-63B §5.1.1 (no complexity mandates)",
        "recommendation": "Remove mandatory lowercase requirement.",
        "penalty": 8,
    },
    {
        "id": "NIST-006",
        "check": lambda p: not p.require_digits,
        "severity": "warning",
        "description": "Mandatory digit requirement contradicts NIST guidance",
        "reference": "NIST SP 800-63B §5.1.1 (no complexity mandates)",
        "recommendation": "Remove mandatory digit requirement.",
        "penalty": 8,
    },
    {
        "id": "NIST-007",
        "check": lambda p: not p.require_special,
        "severity": "warning",
        "description": "Mandatory special character requirement contradicts NIST guidance",
        "reference": "NIST SP 800-63B §5.1.1 (no complexity mandates)",
        "recommendation": "Remove mandatory special character requirement.",
        "penalty": 8,
    },
    {
        "id": "NIST-008",
        "check": lambda p: p.expiry_days == 0,
        "severity": "warning",
        "description": "Mandatory password expiry contradicts NIST guidance",
        "reference": "NIST SP 800-63B §5.1.1",
        "recommendation": "Remove periodic expiry. Only force changes on evidence of compromise.",
        "penalty": 10,
    },
    {
        "id": "NIST-009",
        "check": lambda p: p.check_hibp,
        "severity": "warning",
        "description": "Policy does not check passwords against breach databases",
        "reference": "NIST SP 800-63B §5.1.1.2",
        "recommendation": "Enable HIBP breach checking to block known-compromised passwords.",
        "penalty": 15,
    },
    {
        "id": "NIST-010",
        "check": lambda p: p.check_common_passwords,
        "severity": "warning",
        "description": "Policy does not check against commonly used passwords",
        "reference": "NIST SP 800-63B §5.1.1.2",
        "recommendation": "Enable common password checking (dictionary lists, e.g. from SecLists).",
        "penalty": 10,
    },
    {
        "id": "NIST-011",
        "check": lambda p: not p.allow_hints,
        "severity": "warning",
        "description": "Password hints are enabled, which weaken security",
        "reference": "NIST SP 800-63B §5.1.1.1",
        "recommendation": "Disable password hints entirely.",
        "penalty": 10,
    },
    {
        "id": "NIST-012",
        "check": lambda p: p.allow_unicode,
        "severity": "info",
        "description": "Unicode characters are not allowed, restricting password space",
        "reference": "NIST SP 800-63B §5.1.1",
        "recommendation": "Allow all Unicode characters to support broader character sets.",
        "penalty": 5,
    },
]


def load_policy(path: Path) -> PolicyConfig:
    """Load and validate a policy JSON file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in policy file: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"Cannot read policy file: {exc}") from exc

    rules = data.get("rules", {})

    required_fields = ["name"]
    for f in required_fields:
        if f not in data:
            raise ValueError(f"Policy file missing required field: '{f}'")

    return PolicyConfig(
        name=data.get("name", "Unnamed Policy"),
        version=str(data.get("version", "1.0")),
        min_length=int(rules.get("min_length", 8)),
        max_length=int(rules.get("max_length", 128)),
        require_uppercase=bool(rules.get("require_uppercase", False)),
        require_lowercase=bool(rules.get("require_lowercase", False)),
        require_digits=bool(rules.get("require_digits", False)),
        require_special=bool(rules.get("require_special", False)),
        max_consecutive_repeated=int(rules.get("max_consecutive_repeated", 0)),
        expiry_days=int(rules.get("expiry_days", 0)),
        check_hibp=bool(rules.get("check_hibp", True)),
        check_common_passwords=bool(rules.get("check_common_passwords", True)),
        min_entropy_bits=float(rules.get("min_entropy_bits", 0)),
        allow_unicode=bool(rules.get("allow_unicode", True)),
        allow_hints=bool(rules.get("allow_hints", False)),
    )


def evaluate_policy(policy: PolicyConfig) -> PolicyEvaluation:
    """Evaluate a policy configuration against NIST SP 800-63B."""
    violations: list[PolicyRule] = []
    passes: list[PolicyRule] = []
    score = 100

    for rule_def in _NIST_RULES:
        passes_check: bool = rule_def["check"](policy)
        rule = PolicyRule(
            rule_id=rule_def["id"],
            description=rule_def["description"],
            severity=rule_def["severity"] if not passes_check else "pass",
            nist_reference=rule_def["reference"],
            recommendation=rule_def["recommendation"],
        )
        if passes_check:
            passes.append(rule)
        else:
            violations.append(rule)
            score -= rule_def["penalty"]

    score = max(0, min(100, score))
    has_critical = any(v.severity == "critical" for v in violations)
    nist_compliant = not has_critical and score >= 70

    recommendations: list[str] = []
    # Complexity rules are often grouped — consolidate the message
    complexity_violations = [v for v in violations if v.rule_id in ("NIST-004", "NIST-005", "NIST-006", "NIST-007")]
    if len(complexity_violations) >= 2:
        recommendations.append(
            "Multiple mandatory complexity rules detected. NIST SP 800-63B explicitly discourages "
            "complexity mandates — they increase user frustration without meaningfully improving security. "
            "Replace them with a minimum-length requirement and breach-list checking."
        )
    for v in violations:
        if v.rule_id not in ("NIST-004", "NIST-005", "NIST-006", "NIST-007") or len(complexity_violations) < 2:
            recommendations.append(f"[{v.rule_id}] {v.recommendation}")

    return PolicyEvaluation(
        policy=policy,
        compliance_score=score,
        nist_compliant=nist_compliant,
        violations=violations,
        passes=passes,
        recommendations=recommendations,
    )
