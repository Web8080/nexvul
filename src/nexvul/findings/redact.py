"""Secret redaction for snippets (SR-24, T-24).

Snippets in findings come from the scanned repository. A snippet can contain a credential that a
rule points at (for example a hard-coded API key next to an MCP client). Before a snippet reaches
any output it is length-capped, then secret-shaped substrings are replaced by a marker that keeps
a short prefix, the length and a hash, so two reports can still be compared without the secret.

Regex discipline (SR-09, architecture §5.5): every pattern below is a fixed prefix or a bounded
character class followed by a single bounded repetition; there are no nested quantifiers and no
alternation inside a repeated group. Patterns are applied only to text already capped at
``MAX_SNIPPET_CHARS`` characters. Redaction is heuristic (threat-model residual: Low-Medium).
"""

from __future__ import annotations

import hashlib
import re
from typing import Final

from nexvul.core import limits

#: Known token shapes: a literal prefix followed by a bounded run of token characters.
_TOKEN_PATTERN: Final = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(sk-ant-|sk-proj-|sk-|ghp_|gho_|ghs_|ghu_|github_pat_|xox[abposr]-|AKIA|ASIA|AIza|glpat-|hf_)"
    r"[A-Za-z0-9_\-]{12,200}"
)

#: ``password = "..."`` style assignments: a credential-like key, an operator, a quoted value.
_ASSIGNMENT_PATTERN: Final = re.compile(
    r"(?i)(password|passwd|secret|token|api_key|apikey|access_key|private_key|auth)"
    r"([A-Za-z0-9_]{0,20}[\"']?[ ]{0,4}[:=][ ]{0,4}[\"'])"
    r"([^\"'\s]{6,200})"
)

#: ``Bearer <token>`` in headers.
_BEARER_PATTERN: Final = re.compile(r"(?i)(bearer[ ]{1,4})([A-Za-z0-9_\-\.=]{12,200})")

_KEEP_PREFIX: Final = 4


def _marker(secret: str) -> str:
    digest = hashlib.sha256(secret.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    return f"{secret[:_KEEP_PREFIX]}[redacted {len(secret)} chars sha256:{digest}]"


def redact_secrets(text: str) -> str:
    """Replace secret-shaped substrings. ``text`` must already be length-capped."""
    if len(text) > limits.MAX_SNIPPET_CHARS * 2:
        text = text[: limits.MAX_SNIPPET_CHARS * 2]
    text = _BEARER_PATTERN.sub(lambda m: m.group(1) + _marker(m.group(2)), text)
    text = _TOKEN_PATTERN.sub(lambda m: _marker(m.group(0)), text)
    return _ASSIGNMENT_PATTERN.sub(
        lambda m: (
            m.group(0)
            if "[redacted" in m.group(3)
            else m.group(1) + m.group(2) + _marker(m.group(3))
        ),
        text,
    )
