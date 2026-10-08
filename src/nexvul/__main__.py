"""``python -m nexvul`` entry point with isolated-startup guard (architecture §2.2, SR-02, T-01b).

Only ``sys`` and ``os`` (already loaded by the interpreter) are imported before the check.

``python -m nexvul`` without ``-P``/``-I`` puts the current directory first on ``sys.path``; if the
current directory is a hostile repository, its ``yaml.py`` or ``click.py`` would shadow nexvul's
dependencies. In that case we re-execute the interpreter with ``-P -E`` so dependencies are
imported from a clean path. ``-I`` is not forced because it also disables user site-packages,
which would break ``pip install --user`` installs.

Residual (documented): the ``nexvul`` package itself has already been imported by the time this
code runs, so a hostile ``./nexvul/`` package in the CWD runs before any guard. That is why the
console script (``nexvul``), not ``python -m nexvul``, is the documented invocation, and why the
supervisor also asserts that no loaded module lives under the scan root (core/startup.py).
"""

import os
import sys

_REEXEC_MARKER = "NEXVUL_STARTUP_REEXEC"
_EXIT_INTERNAL_ERROR = 4


def _needs_reexec() -> bool:
    return not (sys.flags.safe_path or sys.flags.isolated)


def _reexec() -> None:
    if os.environ.get(_REEXEC_MARKER) == "1":
        # We already re-executed and the interpreter still is not in safe-path mode: fail closed
        # rather than loop or continue with an unsafe sys.path.
        sys.stderr.write("nexvul: could not establish an isolated sys.path; refusing to run\n")
        sys.exit(_EXIT_INTERNAL_ERROR)
    env = dict(os.environ)
    env[_REEXEC_MARKER] = "1"
    argv = [sys.executable, "-P", "-E", "-m", "nexvul", *sys.argv[1:]]
    os.execve(sys.executable, argv, env)


def _main() -> None:
    if _needs_reexec():
        _reexec()
    from nexvul.cli.main import main

    main()


if __name__ == "__main__":
    _main()
