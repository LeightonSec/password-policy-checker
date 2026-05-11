"""Tests for policy loading and NIST compliance evaluation."""

import json
from pathlib import Path

import pytest

from checker.policy import evaluate_policy, load_policy


def _write_policy(tmp_path: Path, rules: dict, name: str = "Test Policy") -> Path:
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"name": name, "version": "1.0", "rules": rules}))
    return p


class TestLoadPolicy:
    def test_loads_valid_policy(self, sample_policy_nist):
        cfg = load_policy(sample_policy_nist)
        assert cfg.name == "NIST Compliant"
        assert cfg.min_length == 15

    def test_defaults_applied_for_missing_fields(self, tmp_path):
        p = tmp_path / "minimal.json"
        p.write_text('{"name": "Minimal"}')
        cfg = load_policy(p)
        assert cfg.min_length == 8
        assert cfg.allow_unicode is True

    def test_raises_on_invalid_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not valid json")
        with pytest.raises(ValueError, match="Invalid JSON"):
            load_policy(p)

    def test_raises_on_missing_name(self, tmp_path):
        p = tmp_path / "noname.json"
        p.write_text('{"version": "1.0", "rules": {}}')
        with pytest.raises(ValueError, match="name"):
            load_policy(p)

    def test_raises_on_missing_file(self, tmp_path):
        p = tmp_path / "nonexistent.json"
        with pytest.raises(ValueError, match="Cannot read"):
            load_policy(p)


class TestEvaluatePolicy:
    def test_nist_compliant_policy_high_score(self, sample_policy_nist):
        cfg = load_policy(sample_policy_nist)
        result = evaluate_policy(cfg)
        assert result.compliance_score >= 80
        assert result.nist_compliant is True

    def test_strict_legacy_policy_low_score(self, sample_policy_strict):
        cfg = load_policy(sample_policy_strict)
        result = evaluate_policy(cfg)
        assert result.compliance_score < 60

    def test_min_length_below_8_is_critical(self, tmp_path):
        p = _write_policy(tmp_path, {"min_length": 6})
        cfg = load_policy(p)
        result = evaluate_policy(cfg)
        critical = [v for v in result.violations if v.severity == "critical"]
        assert len(critical) > 0

    def test_min_length_8_no_critical(self, tmp_path):
        p = _write_policy(tmp_path, {"min_length": 8, "max_length": 64, "check_hibp": True, "check_common_passwords": True})
        cfg = load_policy(p)
        result = evaluate_policy(cfg)
        critical = [v for v in result.violations if v.severity == "critical"]
        assert len(critical) == 0

    def test_mandatory_complexity_flagged(self, tmp_path):
        p = _write_policy(tmp_path, {
            "min_length": 8,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digits": True,
            "require_special": True,
        })
        cfg = load_policy(p)
        result = evaluate_policy(cfg)
        violation_ids = {v.rule_id for v in result.violations}
        assert "NIST-004" in violation_ids
        assert "NIST-005" in violation_ids
        assert "NIST-006" in violation_ids
        assert "NIST-007" in violation_ids

    def test_expiry_flagged(self, tmp_path):
        p = _write_policy(tmp_path, {"min_length": 8, "expiry_days": 90})
        cfg = load_policy(p)
        result = evaluate_policy(cfg)
        violation_ids = {v.rule_id for v in result.violations}
        assert "NIST-008" in violation_ids

    def test_no_hibp_check_flagged(self, tmp_path):
        p = _write_policy(tmp_path, {"min_length": 8, "check_hibp": False})
        cfg = load_policy(p)
        result = evaluate_policy(cfg)
        violation_ids = {v.rule_id for v in result.violations}
        assert "NIST-009" in violation_ids

    def test_password_hints_flagged(self, tmp_path):
        p = _write_policy(tmp_path, {"min_length": 8, "allow_hints": True})
        cfg = load_policy(p)
        result = evaluate_policy(cfg)
        violation_ids = {v.rule_id for v in result.violations}
        assert "NIST-011" in violation_ids

    def test_max_length_below_64_flagged(self, tmp_path):
        p = _write_policy(tmp_path, {"min_length": 8, "max_length": 20})
        cfg = load_policy(p)
        result = evaluate_policy(cfg)
        violation_ids = {v.rule_id for v in result.violations}
        assert "NIST-003" in violation_ids

    def test_recommendations_not_empty_for_violations(self, sample_policy_strict):
        cfg = load_policy(sample_policy_strict)
        result = evaluate_policy(cfg)
        assert len(result.recommendations) > 0

    def test_score_clamped_0_100(self, sample_policy_strict):
        cfg = load_policy(sample_policy_strict)
        result = evaluate_policy(cfg)
        assert 0 <= result.compliance_score <= 100
