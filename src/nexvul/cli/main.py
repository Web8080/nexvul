"""nexvul CLI: ``scan``, ``rules``, ``explain``, ``doctor``, ``version``.

Exit codes follow OD-06 (see ``nexvul.core.completeness.ExitCode``): 0 complete and nothing at or
above ``--fail-on``; 1 complete with findings at or above it; 2 usage or configuration error
(nothing scanned); 3 scan incomplete (partial, or nothing to analyse); 4 internal error; 130
interrupted. Precedence 2 > 4 > 3 > 1 > 0. No Python traceback ever reaches the user.

Streams (screen-inventory R6): the report goes to stdout (or to ``--output``); warnings, errors
and status lines go to stderr, so ``nexvul scan --format json . > f.json`` is always valid JSON.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Callable, Mapping
from typing import TextIO

import click

from nexvul import __version__
from nexvul.core.completeness import ExitCode
from nexvul.core.config import SEVERITIES, ConfigError, ci_mode_from_env
from nexvul.core.discovery import DiscoveryError
from nexvul.core.sanitize import display_path, display_text
from nexvul.core.scan import ScanOptions, ScanUsageError, run_scan
from nexvul.core.startup import ModuleShadowingError
from nexvul.core.workers import WorkerStartupError
from nexvul.reporting import tokens as tk
from nexvul.reporting.json_report import render_json
from nexvul.reporting.output import OutputRefusedError, prepare_output, write_output
from nexvul.reporting.terminal import (
    TerminalStyle,
    render_scan,
    status_line,
    suppression_warnings,
)
from nexvul.reporting.utility import (
    doctor_checks,
    normalise_rule_id,
    render_doctor,
    render_explain,
    render_rules,
    unknown_rule_message,
)
from nexvul.rules.registry import Registry, builtin_registry

_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

_EPILOG = (
    "A clean nexvul result never proves that an AI-agent application is secure. "
    "nexvul never executes, imports or evaluates the code it scans."
)

_SCAN_EPILOG = """\b
Exit codes
  0  scan complete, no findings at or above --fail-on
  1  scan complete, findings at or above --fail-on
  2  usage or configuration error (nothing scanned)
  3  scan incomplete (files not analysed, limits hit, or nothing to analyse)
  4  internal error in nexvul
A clean nexvul result does not prove that an application is secure.
"""

_BUG_URL = "https://github.com/<owner>/nexvul/issues/new?template=bug.yml"

#: Registry used by every command. Tests replace it; nothing else may (DEC-0004 §4).
registry_factory: Callable[[], Registry] = builtin_registry


def _emit(stream: TextIO, text: str) -> None:
    """Write without ever raising on an encoding the terminal cannot show."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        safe = text.encode(encoding, "backslashreplace").decode(encoding, "replace")
    except LookupError:
        safe = text.encode("ascii", "backslashreplace").decode("ascii")
    stream.write(safe)
    stream.flush()


def _err(text: str) -> None:
    _emit(sys.stderr, text if text.endswith("\n") else text + "\n")


def _width() -> int:
    try:
        return shutil.get_terminal_size((tk.DEFAULT_WIDTH_UNKNOWN, 24)).columns
    except (OSError, ValueError):  # pragma: no cover - defensive
        return tk.DEFAULT_WIDTH_UNKNOWN


def terminal_style(
    env: Mapping[str, str], stream: TextIO, *, no_color: bool, verbose: bool, width: int
) -> TerminalStyle:
    """design-system §5.2-5.3: colour only on a TTY, never with NO_COLOR/--no-color/TERM=dumb."""
    is_tty = bool(getattr(stream, "isatty", lambda: False)())
    if no_color or "NO_COLOR" in env or env.get("TERM") == "dumb":
        color = False
    elif "FORCE_COLOR" in env:
        color = True
    else:
        color = is_tty
    encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
    ascii_mode = (not color) or env.get("NEXVUL_ASCII") == "1" or encoding not in ("utf8", "")
    return TerminalStyle(
        width=width, color=color, plain=not color, ascii=ascii_mode, verbose=verbose
    )


def _ci_reason(flag: bool, env: Mapping[str, str]) -> tuple[bool, str]:
    if flag:
        return True, "--ci"
    if ci_mode_from_env(env):
        name = "GITHUB_ACTIONS" if env.get("GITHUB_ACTIONS", "").lower() == "true" else "CI"
        return True, f"detected from {name}"
    return False, ""


@click.group(context_settings=_CONTEXT_SETTINGS, epilog=_EPILOG)
def cli() -> None:
    """nexvul: local-first static security scanner for AI-agent applications."""


@cli.command()
def version() -> None:
    """Print the nexvul version."""
    click.echo(f"nexvul {__version__}")


@cli.command(epilog=_SCAN_EPILOG)
@click.argument("path", metavar="PATH")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["terminal", "json"]),
    default="terminal",
    show_default=True,
    help="Report format.",
)
@click.option("--output", "output", metavar="FILE", help="Write the report to FILE.")
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(SEVERITIES),
    default=None,
    help="Lowest severity that makes the scan exit 1 (default: high).",
)
@click.option(
    "--ci", "ci_flag", is_flag=True, help="CI mode (also on when CI or GITHUB_ACTIONS is true)."
)
@click.option(
    "--allow-partial",
    is_flag=True,
    help="Do not exit 3 for a partial scan. The report still says PARTIAL SCAN.",
)
@click.option(
    "--verbose", is_flag=True, help="Show effective config, timings and every skipped file."
)
@click.option("--no-color", is_flag=True, help="No colour (also NO_COLOR, TERM=dumb, non-TTY).")
@click.option(
    "--force", is_flag=True, help="Overwrite an existing --output file that is not a nexvul report."
)
def scan(  # noqa: PLR0917 - click passes every option as a parameter
    path: str,
    fmt: str,
    output: str | None,
    fail_on: str | None,
    ci_flag: bool,
    allow_partial: bool,
    verbose: bool,
    no_color: bool,
    force: bool,
) -> int:
    """Scan PATH (a directory) and report findings and scan completeness."""
    env = os.environ
    ci, ci_reason = _ci_reason(ci_flag, env)
    target = None
    if output is not None:
        try:
            target = prepare_output(output, scan_root=path, explicit=True, force=force, fmt=fmt)
        except OutputRefusedError as exc:
            hint = f"\n  {exc.hint}" if exc.hint else ""
            _err(f"nexvul: {exc.message}{hint}\n\nNothing was scanned. Exit code 2.")
            return ExitCode.USAGE_ERROR
    try:
        result = run_scan(
            ScanOptions(
                root=path,
                ci=ci,
                ci_reason=ci_reason,
                fail_on=fail_on,
                allow_partial=allow_partial,
                registry=registry_factory(),
            )
        )
    except ScanUsageError as exc:
        _err(
            f"nexvul: {exc}\n  Usage: nexvul scan [OPTIONS] PATH   Run nexvul scan --help for "
            "options.\n\nNothing was scanned. Exit code 2."
        )
        return ExitCode.USAGE_ERROR
    except ConfigError as exc:
        _err(f"nexvul: config error in .nexvul.yml\n  {exc}\n\nNothing was scanned. Exit code 2.")
        return ExitCode.USAGE_ERROR
    except DiscoveryError as exc:
        _err(
            f"nexvul: cannot scan {display_path(path)}: {exc}\n\nNothing was scanned. Exit code 2."
        )
        return ExitCode.USAGE_ERROR
    except (ModuleShadowingError, WorkerStartupError) as exc:
        _err(
            f"nexvul: {display_text(str(exc), max_chars=300)}\n  Run nexvul from outside the "
            "scanned directory, installed in its own environment (pipx install nexvul).\n\n"
            "No result was produced. Exit code 4."
        )
        return ExitCode.INTERNAL_ERROR

    for warning in suppression_warnings(result):
        _err(warning)
    to_file = target is not None
    if fmt == "json":
        pretty = not to_file and bool(getattr(sys.stdout, "isatty", lambda: False)())
        text = render_json(result, pretty=pretty)
    else:
        style = terminal_style(
            env, sys.stdout, no_color=no_color or to_file, verbose=verbose, width=_width()
        )
        text = render_scan(result, style)
    if target is not None:
        write_output(target, text.encode("utf-8"))
        kind = "JSON" if fmt == "json" else "text"
        _err(f"nexvul: wrote {target.shown} ({kind}, {len(result.findings)} findings)")
        _err(status_line(result))
    else:
        _emit(sys.stdout, text)
    return result.exit_code


@cli.command()
def rules() -> int:
    """List the built-in rules."""
    _emit(sys.stdout, render_rules(registry_factory(), width=_width()))
    return ExitCode.OK


@cli.command()
@click.argument("rule_id", metavar="RULE")
def explain(rule_id: str) -> int:
    """Explain one rule (for example: nexvul explain NEX007)."""
    registry = registry_factory()
    normalised = normalise_rule_id(rule_id)
    rule = registry.get(normalised) if normalised else None
    if rule is None:
        _err(unknown_rule_message(rule_id, registry))
        return ExitCode.USAGE_ERROR
    _emit(sys.stdout, render_explain(rule, width=_width()))
    return ExitCode.OK


@cli.command()
def doctor() -> int:
    """Check nexvul's installation (not your code)."""
    checks = doctor_checks(registry_factory(), cwd=os.getcwd(), prefix=sys.prefix)
    text, code = render_doctor(checks, width=_width())
    _emit(sys.stdout, text)
    return code


def main(argv: list[str] | None = None) -> None:
    """Console-script entry point. Never lets a Python traceback reach the user."""
    try:
        rc = cli.main(args=argv, prog_name="nexvul", standalone_mode=False)
    except click.exceptions.Exit as exc:
        sys.exit(exc.exit_code)
    except click.exceptions.Abort:
        _err("nexvul: interrupted. No result was produced. Exit code 130.")
        sys.exit(ExitCode.INTERRUPTED)
    except click.ClickException as exc:
        exc.show()
        sys.exit(ExitCode.USAGE_ERROR)
    except KeyboardInterrupt:
        _err("nexvul: scan interrupted. No result was produced. Exit code 130.")
        sys.exit(ExitCode.INTERRUPTED)
    except Exception as exc:
        name = display_text(type(exc).__name__, max_chars=60)
        _err(
            f"nexvul stopped unexpectedly (internal error: {name}).\n"
            "  This is a bug in nexvul, not in your code.\n\n"
            f"  Report it: {_BUG_URL}\n"
            "  Include the output of: nexvul doctor\n"
            "  Do not attach source code you cannot share; nexvul sends nothing anywhere.\n\n"
            "No result was produced. Exit code 4."
        )
        sys.exit(ExitCode.INTERNAL_ERROR)
    sys.exit(rc if isinstance(rc, int) else ExitCode.OK)
