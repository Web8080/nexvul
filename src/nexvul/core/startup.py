"""Module-origin assertion (architecture §2.2 step 2, SR-02, T-01b, MF-06).

Before any file in a scan root is opened, the supervisor checks that no already-loaded module was
imported from inside that root. A hit means the scanned repository shadowed one of nexvul's own
imports (``yaml.py``, ``click/``, ``sitecustomize.py`` ...): nexvul aborts with exit code 4.

Step 1 has no ``scan`` command; ``scan`` (step 2) must call :func:`assert_no_module_from_roots`
for every root after argument parsing and before discovery.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import ModuleType

from nexvul.core.sanitize import display_text


@dataclass(frozen=True)
class ShadowedModule:
    module: str
    origin: str


class ModuleShadowingError(Exception):
    """A loaded module lives under a scan root (fail closed, exit code 4)."""

    def __init__(self, hits: tuple[ShadowedModule, ...]) -> None:
        self.hits = hits
        names = ", ".join(display_text(h.module, max_chars=80) for h in hits[:5])
        super().__init__(
            f"refusing to scan: module(s) {names} were loaded from inside the scan root"
        )


def _module_files(module: ModuleType) -> list[str]:
    files: list[str] = []
    origin = getattr(module, "__file__", None)
    if isinstance(origin, str):
        files.append(origin)
    paths = getattr(module, "__path__", None)
    if paths is not None:
        try:
            files.extend(p for p in list(paths) if isinstance(p, str))
        except TypeError:  # exotic namespace path objects
            pass
    return files


def find_modules_under_roots(
    roots: Iterable[str], modules: Mapping[str, ModuleType | None] | None = None
) -> tuple[ShadowedModule, ...]:
    """Return every loaded module whose file or package path resolves inside a root."""
    resolved_roots = [os.path.realpath(r).rstrip("/") + "/" for r in roots]
    mods = dict(sys.modules if modules is None else modules)
    hits: list[ShadowedModule] = []
    for name in sorted(mods):
        module = mods[name]
        if module is None:
            continue
        for path in _module_files(module):
            real = os.path.realpath(path)
            if any(real.startswith(root) or real + "/" == root for root in resolved_roots):
                hits.append(ShadowedModule(name, real))
                break
    return tuple(hits)


def assert_no_module_from_roots(
    roots: Iterable[str], modules: Mapping[str, ModuleType | None] | None = None
) -> None:
    hits = find_modules_under_roots(roots, modules)
    if hits:
        raise ModuleShadowingError(hits)
