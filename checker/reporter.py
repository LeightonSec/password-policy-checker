"""Terminal, JSON, and Markdown output for all evaluation modes."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from .evaluator import PasswordEvaluation
from .policy import PolicyEvaluation, PolicySeverity
from .batch import BatchResult

console = Console()
err_console = Console(stderr=True)


# ── colour helpers ─────────────────────────────────────────────────────────────

_RATING_COLOUR = {
    "Very Weak": "bold red",
    "Weak": "red",
    "Fair": "yellow",
    "Good": "bright_green",
    "Strong": "green",
    "Very Strong": "bold green",
}

_SEVERITY_COLOUR: dict[str, str] = {
    "critical": "bold red",
    "warning": "yellow",
    "info": "cyan",
    "pass": "green",
}

_SEVERITY_ICON: dict[str, str] = {
    "critical": "✗",
    "warning": "⚠",
    "info": "ℹ",
    "pass": "✓",
}

_SCORE_BAR_WIDTH = 30


def _score_bar(score: int) -> Text:
    filled = round(_SCORE_BAR_WIDTH * score / 100)
    bar = Text()
    colour = "red" if score < 40 else "yellow" if score < 60 else "green"
    bar.append("█" * filled, style=colour)
    bar.append("░" * (_SCORE_BAR_WIDTH - filled), style="dim")
    bar.append(f"  {score}/100", style="bold")
    return bar


# ── password evaluation ────────────────────────────────────────────────────────

def print_password_evaluation(result: PasswordEvaluation) -> None:
    """Pretty-print a single password evaluation to the terminal."""
    rating_colour = _RATING_COLOUR.get(result.rating, "white")

    # Header panel
    header = Text()
    header.append("Rating: ", style="bold")
    header.append(result.rating, style=rating_colour)
    header.append("   ")
    header.append(_score_bar(result.score))

    console.print(Panel(header, title="[bold]Password Evaluation[/bold]", border_style="blue"))

    # Composition table
    comp_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    comp_table.add_column("Property", style="dim", width=24)
    comp_table.add_column("Value")

    comp_table.add_row("Length", f"{result.password_length} characters")
    comp_table.add_row("Entropy", f"{result.entropy_bits:.1f} bits  (charset ~{result.charset_size} chars)")

    char_flags = []
    if result.has_lowercase:
        char_flags.append("[green]a–z[/green]")
    if result.has_uppercase:
        char_flags.append("[green]A–Z[/green]")
    if result.has_digits:
        char_flags.append("[green]0–9[/green]")
    if result.has_special:
        char_flags.append("[green]!@#…[/green]")
    if result.has_unicode:
        char_flags.append("[cyan]unicode[/cyan]")
    comp_table.add_row("Character types", " ".join(char_flags) if char_flags else "[red]none[/red]")

    common_val = "[bold red]Yes — commonly used password[/bold red]" if result.is_common else "[green]No[/green]"
    comp_table.add_row("Common password", common_val)

    if result.hibp_checked:
        if result.hibp_error:
            hibp_val = f"[yellow]Check failed: {result.hibp_error}[/yellow]"
        elif result.is_breached:
            hibp_val = f"[bold red]BREACHED — seen {result.breach_count:,} times in leaks[/bold red]"
        else:
            hibp_val = "[green]Not found in HIBP database[/green]"
    else:
        hibp_val = "[dim]Skipped (--no-hibp)[/dim]"
    comp_table.add_row("Breach database", hibp_val)

    if result.patterns:
        comp_table.add_row("Patterns detected", "[yellow]" + ", ".join(result.patterns) + "[/yellow]")
    else:
        comp_table.add_row("Patterns detected", "[green]None[/green]")

    console.print(comp_table)

    # Crack time table
    ct = result.crack_times
    ct_table = Table(title="Estimated Crack Times", box=box.ROUNDED, border_style="dim")
    ct_table.add_column("Attack Scenario", style="cyan")
    ct_table.add_column("Time")
    ct_table.add_column("Notes", style="dim")

    ct_table.add_row("Online (throttled)", ct.online_throttled, "100 attempts/hour, account lockout")
    ct_table.add_row("Online (no limit)", ct.online_unthrottled, "1,000 guesses/second")
    ct_table.add_row("Offline (slow hash)", ct.offline_slow, "bcrypt/Argon2, 10k/s per GPU")
    ct_table.add_row("Offline (fast hash)", ct.offline_fast, "MD5/SHA-1, 10 billion/s")
    ct_table.add_row("GPU cluster", ct.offline_gpu_cluster, "Nation-state, 10 trillion/s")

    console.print(ct_table)

    # Recommendations
    if result.recommendations:
        rec_text = "\n".join(f"  • {r}" for r in result.recommendations)
        console.print(Panel(rec_text, title="[bold yellow]Recommendations[/bold yellow]", border_style="yellow"))


# ── policy evaluation ──────────────────────────────────────────────────────────

def print_policy_evaluation(result: PolicyEvaluation) -> None:
    """Pretty-print a policy NIST compliance evaluation."""
    score = result.compliance_score
    status_colour = "green" if result.nist_compliant else ("yellow" if score >= 50 else "red")
    status_text = "COMPLIANT" if result.nist_compliant else "NON-COMPLIANT"

    header = Text()
    header.append(f"Policy: {result.policy.name}  |  Score: ", style="bold")
    header.append(_score_bar(score))
    header.append(f"  [{status_text}]", style=f"bold {status_colour}")
    console.print(Panel(header, title="[bold]NIST SP 800-63B Policy Evaluation[/bold]", border_style="blue"))

    # Config summary
    cfg = result.policy
    cfg_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    cfg_table.add_column("Setting", style="dim", width=30)
    cfg_table.add_column("Value")

    def yn(val: bool, invert: bool = False) -> str:
        good = not val if invert else val
        colour = "green" if good else "red"
        return f"[{colour}]{'Yes' if val else 'No'}[/{colour}]"

    cfg_table.add_row("Min / max length", f"{cfg.min_length} / {cfg.max_length}")
    cfg_table.add_row("Require uppercase", yn(cfg.require_uppercase, invert=True))
    cfg_table.add_row("Require lowercase", yn(cfg.require_lowercase, invert=True))
    cfg_table.add_row("Require digits", yn(cfg.require_digits, invert=True))
    cfg_table.add_row("Require special chars", yn(cfg.require_special, invert=True))
    cfg_table.add_row("Password expiry (days)", str(cfg.expiry_days) if cfg.expiry_days else "[green]None (recommended)[/green]")
    cfg_table.add_row("HIBP breach check", yn(cfg.check_hibp))
    cfg_table.add_row("Common password check", yn(cfg.check_common_passwords))
    cfg_table.add_row("Allow Unicode", yn(cfg.allow_unicode))
    cfg_table.add_row("Allow password hints", yn(cfg.allow_hints, invert=True))
    console.print(cfg_table)

    # NIST rule results
    rules_table = Table(title="NIST Rule Evaluation", box=box.ROUNDED, border_style="dim")
    rules_table.add_column("", width=3)
    rules_table.add_column("ID", style="dim", width=12)
    rules_table.add_column("Finding")
    rules_table.add_column("Reference", style="dim")

    all_rules = result.violations + result.passes
    all_rules.sort(key=lambda r: (r.severity == "pass", r.rule_id))

    for rule in all_rules:
        icon = _SEVERITY_ICON[rule.severity]
        colour = _SEVERITY_COLOUR[rule.severity]
        rules_table.add_row(
            f"[{colour}]{icon}[/{colour}]",
            rule.rule_id,
            f"[{colour}]{rule.description}[/{colour}]",
            rule.nist_reference,
        )
    console.print(rules_table)

    # Recommendations
    if result.recommendations:
        rec_text = "\n".join(f"  • {r}" for r in result.recommendations)
        console.print(Panel(rec_text, title="[bold yellow]Recommendations[/bold yellow]", border_style="yellow"))


# ── batch results ──────────────────────────────────────────────────────────────

def print_batch_results(result: BatchResult) -> None:
    """Pretty-print batch evaluation aggregate statistics."""
    console.print(Panel(
        f"[bold]Evaluated {result.evaluated:,} of {result.total:,} passwords[/bold]"
        + (f"  |  [red]{result.errors} errors[/red]" if result.errors else ""),
        title="[bold]Batch Evaluation Summary[/bold]",
        border_style="blue",
    ))

    # Score distribution
    dist_table = Table(title="Score Distribution", box=box.ROUNDED)
    dist_table.add_column("Rating", style="bold")
    dist_table.add_column("Count", justify="right")
    dist_table.add_column("Percentage", justify="right")
    dist_table.add_column("Bar")

    n = result.evaluated or 1
    ratings = [
        ("Very Weak",  result.very_weak,   "red"),
        ("Weak",       result.weak,        "red"),
        ("Fair",       result.fair,        "yellow"),
        ("Good",       result.good,        "bright_green"),
        ("Strong",     result.strong,      "green"),
        ("Very Strong",result.very_strong, "bold green"),
    ]
    for name, count, colour in ratings:
        pct = 100 * count / n
        bar = f"[{colour}]{'█' * round(pct / 5)}[/{colour}]"
        dist_table.add_row(f"[{colour}]{name}[/{colour}]", str(count), f"{pct:.1f}%", bar)
    console.print(dist_table)

    # Summary stats
    stats_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    stats_table.add_column("Metric", style="dim", width=28)
    stats_table.add_column("Value")

    stats_table.add_row("Average score", f"{result.avg_score:.1f}/100")
    stats_table.add_row("Average length", f"{result.avg_length:.1f} characters")
    stats_table.add_row("Average entropy", f"{result.avg_entropy:.1f} bits")
    stats_table.add_row("Common passwords", f"[red]{result.common_count:,}[/red] ({100*result.common_count/n:.1f}%)")

    if result.hibp_checked:
        stats_table.add_row("Breached passwords", f"[red]{result.breached_count:,}[/red] ({100*result.breached_count/n:.1f}%)")
    else:
        stats_table.add_row("Breached passwords", "[dim]HIBP check skipped (use --hibp to enable)[/dim]")

    if result.policy_name:
        pass_pct = 100 * result.policy_pass / n
        stats_table.add_row(
            f"Policy compliance ({result.policy_name})",
            f"[{'green' if pass_pct >= 80 else 'red'}]{result.policy_pass:,}/{n:,} ({pass_pct:.1f}%)[/]",
        )
    console.print(stats_table)

    if result.pattern_hits:
        pat_table = Table(title="Pattern Hits", box=box.SIMPLE)
        pat_table.add_column("Pattern", style="cyan")
        pat_table.add_column("Count", justify="right")
        for pattern, count in sorted(result.pattern_hits.items(), key=lambda x: -x[1]):
            pat_table.add_row(pattern, str(count))
        console.print(pat_table)


# ── export helpers ─────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def export_password_json(result: PasswordEvaluation, path: Path) -> None:
    data = {
        "generated_at": _now_iso(),
        "tool": "password-policy-checker",
        "password_length": result.password_length,
        "score": result.score,
        "rating": result.rating,
        "entropy_bits": result.entropy_bits,
        "charset_size": result.charset_size,
        "composition": {
            "lowercase": result.has_lowercase,
            "uppercase": result.has_uppercase,
            "digits": result.has_digits,
            "special": result.has_special,
            "unicode": result.has_unicode,
        },
        "threats": {
            "is_common": result.is_common,
            "is_breached": result.is_breached,
            "breach_count": result.breach_count,
            "hibp_checked": result.hibp_checked,
            "hibp_error": result.hibp_error,
        },
        "patterns": result.patterns,
        "crack_times": {
            "online_throttled": result.crack_times.online_throttled,
            "online_unthrottled": result.crack_times.online_unthrottled,
            "offline_slow_hash": result.crack_times.offline_slow,
            "offline_fast_hash": result.crack_times.offline_fast,
            "offline_gpu_cluster": result.crack_times.offline_gpu_cluster,
        },
        "recommendations": result.recommendations,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    console.print(f"[green]JSON exported → {path}[/green]")


def export_policy_json(result: PolicyEvaluation, path: Path) -> None:
    data = {
        "generated_at": _now_iso(),
        "tool": "password-policy-checker",
        "policy_name": result.policy.name,
        "compliance_score": result.compliance_score,
        "nist_compliant": result.nist_compliant,
        "violations": [
            {"id": v.rule_id, "severity": v.severity, "description": v.description,
             "reference": v.nist_reference, "recommendation": v.recommendation}
            for v in result.violations
        ],
        "passes": [
            {"id": p.rule_id, "description": p.description, "reference": p.nist_reference}
            for p in result.passes
        ],
        "recommendations": result.recommendations,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    console.print(f"[green]JSON exported → {path}[/green]")


def export_batch_json(result: BatchResult, path: Path) -> None:
    data = {
        "generated_at": _now_iso(),
        "tool": "password-policy-checker",
        "total": result.total,
        "evaluated": result.evaluated,
        "errors": result.errors,
        "avg_score": result.avg_score,
        "avg_length": result.avg_length,
        "avg_entropy": result.avg_entropy,
        "rating_distribution": {
            "very_weak": result.very_weak,
            "weak": result.weak,
            "fair": result.fair,
            "good": result.good,
            "strong": result.strong,
            "very_strong": result.very_strong,
        },
        "threats": {
            "common_count": result.common_count,
            "breached_count": result.breached_count,
            "hibp_checked": result.hibp_checked,
        },
        "policy_compliance": {
            "policy_name": result.policy_name,
            "pass": result.policy_pass,
            "fail": result.policy_fail,
        } if result.policy_name else None,
        "pattern_hits": result.pattern_hits,
        "length_distribution": result.length_distribution,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    console.print(f"[green]JSON exported → {path}[/green]")


def export_password_markdown(result: PasswordEvaluation, path: Path) -> None:
    ct = result.crack_times
    lines = [
        "# Password Evaluation Report",
        f"\n_Generated: {_now_iso()}_\n",
        f"## Overall: {result.rating} ({result.score}/100)\n",
        "## Composition\n",
        f"| Property | Value |",
        f"|---|---|",
        f"| Length | {result.password_length} characters |",
        f"| Entropy | {result.entropy_bits:.1f} bits |",
        f"| Lowercase | {'✓' if result.has_lowercase else '✗'} |",
        f"| Uppercase | {'✓' if result.has_uppercase else '✗'} |",
        f"| Digits | {'✓' if result.has_digits else '✗'} |",
        f"| Special chars | {'✓' if result.has_special else '✗'} |",
        f"| Unicode | {'✓' if result.has_unicode else '✗'} |",
        f"| Common password | {'⚠ Yes' if result.is_common else 'No'} |",
        f"| Breached (HIBP) | {'⚠ Yes — ' + str(result.breach_count) + ' occurrences' if result.is_breached else ('Not checked' if not result.hibp_checked else 'No')} |",
        f"\n## Estimated Crack Times\n",
        f"| Scenario | Time |",
        f"|---|---|",
        f"| Online (throttled) | {ct.online_throttled} |",
        f"| Online (no rate limit) | {ct.online_unthrottled} |",
        f"| Offline slow hash (bcrypt) | {ct.offline_slow} |",
        f"| Offline fast hash (MD5/SHA-1) | {ct.offline_fast} |",
        f"| GPU cluster | {ct.offline_gpu_cluster} |",
    ]
    if result.patterns:
        lines += ["\n## Patterns Detected\n"]
        for p in result.patterns:
            lines.append(f"- {p}")
    lines += ["\n## Recommendations\n"]
    for r in result.recommendations:
        lines.append(f"- {r}")
    lines.append(f"\n---\n_[NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) | "
                 f"[NCSC Password Guidance](https://www.ncsc.gov.uk/collection/passwords)_")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"[green]Markdown exported → {path}[/green]")


def export_batch_markdown(result: BatchResult, path: Path) -> None:
    n = result.evaluated or 1
    lines = [
        "# Batch Password Evaluation Report",
        f"\n_Generated: {_now_iso()}_\n",
        f"**Total passwords:** {result.total}  |  "
        f"**Evaluated:** {result.evaluated}  |  "
        f"**Errors:** {result.errors}\n",
        "## Score Distribution\n",
        "| Rating | Count | Percentage |",
        "|---|---|---|",
        f"| Very Weak | {result.very_weak} | {100*result.very_weak/n:.1f}% |",
        f"| Weak | {result.weak} | {100*result.weak/n:.1f}% |",
        f"| Fair | {result.fair} | {100*result.fair/n:.1f}% |",
        f"| Good | {result.good} | {100*result.good/n:.1f}% |",
        f"| Strong | {result.strong} | {100*result.strong/n:.1f}% |",
        f"| Very Strong | {result.very_strong} | {100*result.very_strong/n:.1f}% |",
        "\n## Aggregate Metrics\n",
        f"- **Average score:** {result.avg_score}/100",
        f"- **Average length:** {result.avg_length:.1f} characters",
        f"- **Average entropy:** {result.avg_entropy:.1f} bits",
        f"- **Common passwords:** {result.common_count:,} ({100*result.common_count/n:.1f}%)",
    ]
    if result.hibp_checked:
        lines.append(f"- **Breached passwords:** {result.breached_count:,} ({100*result.breached_count/n:.1f}%)")
    if result.policy_name:
        lines.append(
            f"- **Policy compliance ({result.policy_name}):** "
            f"{result.policy_pass}/{result.evaluated} ({100*result.policy_pass/n:.1f}%)"
        )
    if result.pattern_hits:
        lines += ["\n## Common Patterns\n", "| Pattern | Occurrences |", "|---|---|"]
        for pattern, count in sorted(result.pattern_hits.items(), key=lambda x: -x[1]):
            lines.append(f"| {pattern} | {count} |")
    lines.append(f"\n---\n_[NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)_")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"[green]Markdown exported → {path}[/green]")
