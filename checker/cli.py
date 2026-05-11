"""CLI entry point for password-policy-checker."""

from __future__ import annotations

import getpass
import sys
from pathlib import Path
from typing import Annotated

import typer

from .batch import evaluate_batch
from .evaluator import evaluate_password
from .policy import evaluate_policy, load_policy
from .reporter import (
    console,
    export_batch_json,
    export_batch_markdown,
    export_password_json,
    export_password_markdown,
    export_policy_json,
    print_batch_results,
    print_password_evaluation,
    print_policy_evaluation,
)

app = typer.Typer(
    name="password-policy-checker",
    help=(
        "Evaluate passwords and organisational password policies against "
        "NIST SP 800-63B, NCSC guidelines, and common security standards.\n\n"
        "Passwords are NEVER logged, stored, or transmitted in full."
    ),
    add_completion=False,
    rich_markup_mode="rich",
)


# ── check ──────────────────────────────────────────────────────────────────────

@app.command()
def check(
    password: Annotated[
        str | None,
        typer.Argument(help="Password to evaluate. Omit to be prompted securely (recommended)."),
    ] = None,
    no_hibp: Annotated[bool, typer.Option("--no-hibp", help="Skip HaveIBeenPwned breach check.")] = False,
    policy_file: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="JSON policy file to evaluate the password against."),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Export format: 'json' or 'markdown'."),
    ] = None,
    export_path: Annotated[
        Path | None,
        typer.Option("--export", "-e", help="File path for export output."),
    ] = None,
) -> None:
    """Evaluate a single password against security standards."""
    if password is not None:
        console.print(
            "[yellow]⚠  Warning: passing a password as a CLI argument may expose it in shell history.[/yellow]"
        )
        pw = password
        password = None  # clear the reference
    elif not sys.stdin.isatty():
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass("Enter password to evaluate: ")

    if not pw:
        console.print("[red]No password provided.[/red]")
        raise typer.Exit(1)

    with console.status("Evaluating password...", spinner="dots"):
        result = evaluate_password(pw, check_hibp_api=not no_hibp)
        pw = "0" * len(pw)
        del pw

    print_password_evaluation(result)

    if policy_file:
        if not policy_file.exists():
            console.print(f"[red]Policy file not found: {policy_file}[/red]")
            raise typer.Exit(1)
        policy_cfg = load_policy(policy_file)
        policy_eval = evaluate_policy(policy_cfg)
        print_policy_evaluation(policy_eval)

    if output and export_path:
        fmt = output.lower()
        if fmt == "json":
            export_password_json(result, export_path)
        elif fmt in ("markdown", "md"):
            export_password_markdown(result, export_path)
        else:
            console.print(f"[red]Unknown output format: '{output}'. Use 'json' or 'markdown'.[/red]")
            raise typer.Exit(1)
    elif output and not export_path:
        export_path = Path(f"password-report.{output.lower().replace('markdown','md')}")
        if output.lower() == "json":
            export_password_json(result, export_path)
        else:
            export_password_markdown(result, export_path)


# ── policy ─────────────────────────────────────────────────────────────────────

@app.command()
def policy(
    policy_file: Annotated[Path, typer.Argument(help="Path to the JSON policy configuration file.")],
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Export format: 'json'."),
    ] = None,
    export_path: Annotated[
        Path | None,
        typer.Option("--export", "-e", help="File path for export output."),
    ] = None,
) -> None:
    """Evaluate an organisational password policy against NIST SP 800-63B."""
    if not policy_file.exists():
        console.print(f"[red]Policy file not found: {policy_file}[/red]")
        raise typer.Exit(1)

    try:
        policy_cfg = load_policy(policy_file)
    except ValueError as exc:
        console.print(f"[red]Failed to load policy: {exc}[/red]")
        raise typer.Exit(1)

    result = evaluate_policy(policy_cfg)
    print_policy_evaluation(result)

    if output:
        dest = export_path or Path(f"policy-report.{output.lower()}")
        if output.lower() == "json":
            export_policy_json(result, dest)
        else:
            console.print("[red]Policy export currently supports 'json' only.[/red]")
            raise typer.Exit(1)

    # Exit with non-zero code if policy has critical violations
    if any(v.severity == "critical" for v in result.violations):
        raise typer.Exit(2)


# ── batch ──────────────────────────────────────────────────────────────────────

@app.command()
def batch(
    passwords_file: Annotated[Path, typer.Argument(help="File containing one password per line.")],
    policy_file: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Optional JSON policy file for compliance checking."),
    ] = None,
    hibp: Annotated[
        bool,
        typer.Option("--hibp/--no-hibp", help="Enable HIBP breach checks (slow for large sets, rate-limited)."),
    ] = False,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Export format: 'json' or 'markdown'."),
    ] = None,
    export_path: Annotated[
        Path | None,
        typer.Option("--export", "-e", help="File path for export output."),
    ] = None,
) -> None:
    """
    Evaluate a batch of passwords and produce aggregate statistics.

    [bold yellow]Security note:[/bold yellow] plaintext passwords in files should be
    treated as sensitive data. Avoid running batch mode on production credential stores.
    HIBP checks are disabled by default to avoid API rate limiting.
    """
    if not passwords_file.exists():
        console.print(f"[red]Passwords file not found: {passwords_file}[/red]")
        raise typer.Exit(1)

    if hibp:
        console.print(
            "[yellow]⚠  HIBP checks enabled for batch mode. This may be slow "
            "and could trigger rate limiting for large files.[/yellow]"
        )

    policy_cfg = None
    if policy_file:
        if not policy_file.exists():
            console.print(f"[red]Policy file not found: {policy_file}[/red]")
            raise typer.Exit(1)
        try:
            policy_cfg = load_policy(policy_file)
        except ValueError as exc:
            console.print(f"[red]Failed to load policy: {exc}[/red]")
            raise typer.Exit(1)

    with console.status("Running batch evaluation...", spinner="dots"):
        result = evaluate_batch(
            path=passwords_file,
            check_hibp_api=hibp,
            policy=policy_cfg,
        )

    print_batch_results(result)

    if output:
        dest = export_path or Path(f"batch-report.{output.lower().replace('markdown','md')}")
        fmt = output.lower()
        if fmt == "json":
            export_batch_json(result, dest)
        elif fmt in ("markdown", "md"):
            export_batch_markdown(result, dest)
        else:
            console.print(f"[red]Unknown output format: '{output}'.[/red]")
            raise typer.Exit(1)


# ── version ────────────────────────────────────────────────────────────────────

@app.command()
def version() -> None:
    """Show version information."""
    from . import __version__
    console.print(f"password-policy-checker v{__version__}")
    console.print("NIST SP 800-63B compliance checker | https://github.com/LeightonSec/password-policy-checker")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
