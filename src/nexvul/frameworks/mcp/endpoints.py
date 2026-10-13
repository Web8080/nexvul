"""Classify an MCP server URL taken from a config file or a constant call argument (step 4).

Pure string analysis: nothing is resolved, fetched or connected to (local-first, SR-23). The
question answered is narrow: *does this literal URL point off the local machine, and is it
cleartext?*

Host classes:

* ``loopback`` - ``localhost`` / ``*.localhost`` (RFC 6761), ``127.0.0.0/8`` in any WHATWG IPv4
  spelling (``127.1``, ``0x7f.0.0.1``, ``2130706433``), ``::1`` and ``::ffff:127.x.x.x``. A
  trailing dot is ignored (``localhost.``). ``localhost.evil.com`` is **not** loopback.
* ``unspecified`` - ``0.0.0.0`` / ``::``. As a *client* destination these reach the local machine
  on Linux and macOS; they are not a remote channel (binding a *server* to them is a different
  check, research M2).
* ``private`` - RFC 1918 / ULA / link-local IP literals, single-label host names (container
  service names such as ``mcp``) and ``.local``, ``.internal``, ``.lan``, ``.home.arpa``,
  ``.cluster.local``, ``.svc`` names. Still off-machine, but often on a trusted network or
  behind a TLS-terminating sidecar (research M8 FP note), so rules lower severity.
* ``remote`` - everything else that parses.
* ``unknown`` - the host is templated (``${VAR}``, ``{{x}}``, ``$env:``), empty, or does not
  parse. Rules do not report these (documented false negatives: env-driven URLs).

The display form never contains user-info or query values (they may hold credentials).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from urllib.parse import unquote, urlsplit

from nexvul.findings.redact import redact_secrets

MAX_URL_CHARS: Final = 4096
_DISPLAY_PATH_CHARS: Final = 60
_TEMPLATE_MARKERS: Final = ("${", "{{", "$env:", "%24%7b", "%7b%7b")
_PRIVATE_SUFFIXES: Final = (".local", ".internal", ".lan", ".home.arpa", ".cluster.local", ".svc")
_QUERY_CREDENTIAL_KEYS: Final = frozenset(
    {
        "token",
        "access_token",
        "accesstoken",
        "api_key",
        "apikey",
        "api-key",
        "key",
        "auth",
        "authorization",
        "bearer",
        "secret",
        "password",
        "sig",
        "signature",
    }
)


_DIGITS: Final = {
    8: frozenset("01234567"),
    10: frozenset("0123456789"),
    16: frozenset("0123456789abcdefABCDEF"),
}


class HostClass(StrEnum):
    LOOPBACK = "loopback"
    UNSPECIFIED = "unspecified"
    PRIVATE = "private"
    REMOTE = "remote"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Endpoint:
    scheme: str  # lower-cased; "" when absent
    host: str  # lower-cased, percent-decoded, trailing dot removed; "" when unknown
    host_class: HostClass
    has_userinfo: bool
    query_credential: bool  # a credential-looking query parameter name (value never kept)
    display: str  # safe to show: no user-info, no query values

    @property
    def cleartext(self) -> bool:
        return self.scheme == "http"

    @property
    def off_machine(self) -> bool:
        return self.host_class in (HostClass.REMOTE, HostClass.PRIVATE)


def _ipv4_part(label: str) -> int | None:
    """One WHATWG IPv4 number: decimal, ``0x`` hex or leading-``0`` octal. ``None`` if not."""
    text = label
    base = 10
    if text[:2] in ("0x", "0X"):
        base, text = 16, text[2:]
    elif len(text) > 1 and text[0] == "0":
        base, text = 8, text[1:]
    if text == "":
        return 0
    allowed = _DIGITS[base]
    if len(text) > 32 or any(c not in allowed for c in text):
        return None
    return int(text, base)


def _ends_in_number(labels: list[str]) -> bool:
    last = labels[-1]
    if last and last.isascii() and last.isdigit():
        return True
    return last[:2] in ("0x", "0X") and all(c in "0123456789abcdefABCDEF" for c in last[2:])


def whatwg_ipv4(host: str) -> int | bool | None:
    """WHATWG URL host IPv4 parsing. Returns the address as ``int``, ``None`` when the host is
    not an IPv4 address (a domain), or ``False`` when it ends in a number but is invalid (the
    URL would fail to parse in a WHATWG client such as Node's ``fetch``)."""
    labels = host.split(".")
    if len(labels) > 1 and labels[-1] == "":
        labels.pop()
    if not labels or not _ends_in_number(labels):
        return None
    if len(labels) > 4:
        return False
    numbers = [_ipv4_part(label) for label in labels]
    if any(n is None for n in numbers):
        return False
    nums = [n for n in numbers if n is not None]
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return False
    value = nums[-1]
    for i, n in enumerate(nums[:-1]):
        value += n * 256 ** (3 - i)
    return value


def _classify_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> HostClass:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return HostClass.LOOPBACK
    if ip.is_unspecified:
        return HostClass.UNSPECIFIED
    if ip.is_private or ip.is_link_local:
        return HostClass.PRIVATE
    return HostClass.REMOTE


def classify_host(host: str) -> HostClass:
    """Classify an already lower-cased, percent-decoded host (no brackets, no trailing dot)."""
    if not host:
        return HostClass.UNKNOWN
    if ":" in host:
        try:
            return _classify_ip(ipaddress.IPv6Address(host.split("%", 1)[0]))
        except ValueError:
            return HostClass.UNKNOWN
    v4 = whatwg_ipv4(host)
    if v4 is False:
        return HostClass.UNKNOWN
    if isinstance(v4, int) and not isinstance(v4, bool):
        return _classify_ip(ipaddress.IPv4Address(v4))
    if host == "localhost" or host.endswith(".localhost"):
        return HostClass.LOOPBACK
    if "." not in host or host.endswith(_PRIVATE_SUFFIXES):
        return HostClass.PRIVATE
    return HostClass.REMOTE


def _display(scheme: str, host: str, port: str, path: str, *, userinfo: bool, query: bool) -> str:
    shown_host = f"[{host}]" if ":" in host else host
    if len(path) > _DISPLAY_PATH_CHARS:
        path = path[: _DISPLAY_PATH_CHARS - 1] + "…"
    text = f"{scheme}://{'[user-info removed]@' if userinfo else ''}{shown_host}"
    text += f":{port}" if port else ""
    text += path
    text += "?[query removed]" if query else ""
    return redact_secrets(text)


def parse_endpoint(url: str) -> Endpoint | None:
    """Parse a literal URL. ``None`` for non-strings that do not look like URLs at all."""
    raw = url.strip()
    if not raw or len(raw) > MAX_URL_CHARS or "://" not in raw:
        return None
    scheme_part, _, rest = raw.partition("://")
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    lowered = (scheme_part + "://" + authority).lower()
    if any(marker in lowered for marker in _TEMPLATE_MARKERS) or "$" in authority:
        return Endpoint(
            scheme=scheme_part.lower() if scheme_part.isalpha() else "",
            host="",
            host_class=HostClass.UNKNOWN,
            has_userinfo="@" in authority,
            query_credential=False,
            display="(templated URL)",
        )
    try:
        parts = urlsplit(raw)
        hostname = parts.hostname or ""
        port_value = parts.port
    except ValueError:
        return Endpoint(
            scheme=scheme_part.lower(),
            host="",
            host_class=HostClass.UNKNOWN,
            has_userinfo="@" in authority,
            query_credential=False,
            display="(unparseable URL)",
        )
    host = unquote(hostname).lower()
    if host.endswith(".") and len(host) > 1:
        host = host[:-1]
    query_names = {
        unquote(pair.split("=", 1)[0]).strip().lower()
        for pair in parts.query.split("&")
        if pair.strip()
    }
    has_userinfo = "@" in parts.netloc
    port = str(port_value) if port_value is not None else ""
    return Endpoint(
        scheme=parts.scheme.lower(),
        host=host,
        host_class=classify_host(host),
        has_userinfo=has_userinfo,
        query_credential=bool(query_names & _QUERY_CREDENTIAL_KEYS),
        display=_display(
            parts.scheme.lower(),
            host,
            port,
            parts.path,
            userinfo=has_userinfo,
            query=bool(parts.query),
        ),
    )
