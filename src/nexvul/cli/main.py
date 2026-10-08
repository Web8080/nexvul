"""nexvul CLI (Phase 1 step 1: ``version`` and ``--help`` only; there is no ``scan`` yet).

Exit codes follow OD-06 (see ``nexvul.core.completeness.ExitCode``): click usage errors exit 2;
any unexpected exception exits 4 with a short message and no traceback; Ctrl-C exits 130.
"""

from __future__ import annotations

import sys

import click

from nexvul import __version__
from nexvul.core.completeness import ExitCode

_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

_EPILOG = (
    "A clean nexvul result never proves that an AI-agent application is secure. "
    "nexvul never executes, imports or evaluates the code it scans."
)


@click.group(context_settings=_CONTEXT_SETTINGS, epilog=_EPILOG)
def cli() -> None:
    """nexvul: local-first static security scanner for AI-agent applications."""


@cli.command()
def version() -> None:
    """Print the nexvul version."""
    click.echo(f"nexvul {__version__}")


def main(argv: list[str] | None = None) -> None:
    """Console-script entry point. Never lets a Python traceback reach the user."""
    try:
        rc = cli.main(args=argv, prog_name="nexvul", standalone_mode=False)
    except click.exceptions.Exit as exc:
        sys.exit(exc.exit_code)
    except click.exceptions.Abort:
        sys.exit(ExitCode.INTERRUPTED)
    except click.ClickException as exc:
        exc.show()
        sys.exit(ExitCode.USAGE_ERROR)
    except KeyboardInterrupt:
        sys.exit(ExitCode.INTERRUPTED)
    except Exception:
        sys.stderr.write("nexvul: internal error (exit 4). Re-run with a bug report.\n")
        sys.exit(ExitCode.INTERNAL_ERROR)
    sys.exit(rc if isinstance(rc, int) else ExitCode.OK)
