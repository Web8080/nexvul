"""NEX007 (MCP connection without authentication or over cleartext): recogniser, endpoint
classification, Python client detection, finding content, edge cases and goldens.

Fixture-driven positives/negatives live in tests/rules/nex007 (run by
tests/component/rule_engine/test_rule_fixtures.py). This module covers behaviour that needs
generated inputs (huge files, deep nesting), exact finding content, and the reporters.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from rule_fixtures import scan_virtual

from nexvul.core import workers
from nexvul.core.completeness import SkipReason
from nexvul.findings.model import Confidence, Severity
from nexvul.findings.result import ScanResult
from nexvul.frameworks.mcp import (
    HostClass,
    McpClient,
    Transport,
    classify_host,
    find_http_client_calls,
    parse_endpoint,
    recognise_config,
)
from nexvul.frameworks.mcp.endpoints import whatwg_ipv4
from nexvul.parser.json_config import parse_json_config
from nexvul.parser.python import parse_python
from nexvul.reporting.json_report import finding_to_dict, report_dict
from nexvul.reporting.terminal import TerminalStyle, render_scan
from nexvul.rules.asi07.nex007 import META, McpConnectionWithoutAuth
from nexvul.rules.base import RuleContext

REPO = Path(__file__).resolve().parents[2]
GOLDEN = REPO / "tests" / "golden"
UPDATE = os.environ.get("NEXVUL_UPDATE_GOLDEN") == "1"
ESC = chr(0x1B)


def cfg(path: str, doc: object) -> object:
    module = parse_json_config(json.dumps(doc).encode(), path)
    assert module.ok
    return recognise_config(module)


def matches(path: str, doc: object) -> list:  # type: ignore[type-arg]
    module = parse_json_config(json.dumps(doc).encode(), path)
    return list(McpConnectionWithoutAuth().check(RuleContext(modules=(module,))))


def py_matches(src: str) -> list:  # type: ignore[type-arg]
    module = parse_python(src.encode(), "app/c.py")
    return list(McpConnectionWithoutAuth().check(RuleContext(modules=(module,))))


# --- endpoints -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "host_class", "cleartext"),
    [
        ("http://mcp.example.com/mcp", HostClass.REMOTE, True),
        ("HTTPS://MCP.EXAMPLE.COM/mcp", HostClass.REMOTE, False),
        ("http://localhost:8000/mcp", HostClass.LOOPBACK, True),
        ("http://LOCALHOST./mcp", HostClass.LOOPBACK, True),
        ("http://api.localhost/mcp", HostClass.LOOPBACK, True),
        ("http://localhost.evil.example/mcp", HostClass.REMOTE, True),
        ("http://127.0.0.1.evil.example/mcp", HostClass.REMOTE, True),
        ("http://127.5.6.7/mcp", HostClass.LOOPBACK, True),
        ("http://127.1/", HostClass.LOOPBACK, True),
        ("http://0x7F.0.0.1/", HostClass.LOOPBACK, True),
        ("http://0177.0.0.1/", HostClass.LOOPBACK, True),
        ("http://2130706433/", HostClass.LOOPBACK, True),
        ("http://[::1]:3000/", HostClass.LOOPBACK, True),
        ("http://[::ffff:127.0.0.1]/", HostClass.LOOPBACK, True),
        ("http://0.0.0.0:8000/", HostClass.UNSPECIFIED, True),
        ("http://[::]/", HostClass.UNSPECIFIED, True),
        ("http://10.1.2.3/", HostClass.PRIVATE, True),
        ("http://192.168.0.10/", HostClass.PRIVATE, True),
        ("http://169.254.169.254/", HostClass.PRIVATE, True),
        ("http://[fd00::1]/", HostClass.PRIVATE, True),
        ("http://mcp:8080/", HostClass.PRIVATE, True),
        ("http://svc.ns.svc.cluster.local/", HostClass.PRIVATE, True),
        ("http://printer.local/", HostClass.PRIVATE, True),
        ("http://[2606:4700:4700::1111]/", HostClass.REMOTE, True),
        ("http://8.8.8.8/", HostClass.REMOTE, True),
        ("http://256.1.1.1/", HostClass.UNKNOWN, True),
        ("http://1.2.3.4.5/", HostClass.UNKNOWN, True),
        ("http://0x7g.1/", HostClass.UNKNOWN, True),
        ("http://local%68ost/", HostClass.LOOPBACK, True),
        ("https://${HOST}/mcp", HostClass.UNKNOWN, False),
        ("http://{{host}}/mcp", HostClass.UNKNOWN, True),
        ("http://[zz::1/", HostClass.UNKNOWN, True),
        ("http://host.example:99999/", HostClass.UNKNOWN, True),
    ],
)
def test_endpoint_classification(url: str, host_class: HostClass, cleartext: bool) -> None:
    endpoint = parse_endpoint(url)
    assert endpoint is not None
    assert endpoint.host_class is host_class
    assert endpoint.cleartext is cleartext


@pytest.mark.parametrize("url", ["", "mcp.example.com", "x" * 5000, "  "])
def test_non_urls(url: str) -> None:
    assert parse_endpoint(url) is None


def test_display_never_shows_userinfo_or_query_values() -> None:
    endpoint = parse_endpoint("https://svc:hunter2@mcp.example.com:8443/p?token=abc123&x=1#frag")
    assert endpoint is not None
    assert endpoint.has_userinfo and endpoint.query_credential
    assert "hunter2" not in endpoint.display and "abc123" not in endpoint.display
    assert endpoint.display == (
        "https://[user-info removed]@mcp.example.com:8443/p?[query removed]"
    )
    long = parse_endpoint("http://h.example/" + "a" * 200)
    assert long is not None and long.display.endswith("…") and len(long.display) < 100
    assert parse_endpoint("http://[::1]/x") is not None


def test_whatwg_ipv4_helpers() -> None:
    assert whatwg_ipv4("example.com") is None
    assert whatwg_ipv4("1.2.3.4.") == 0x01020304
    assert whatwg_ipv4("0x") == 0
    assert whatwg_ipv4("1.2.3.4.5") is False
    assert classify_host("") is HostClass.UNKNOWN


# --- recogniser ----------------------------------------------------------------------------------

SERVERS = {"mcpServers": {"a": {"url": "http://mcp.example.com/mcp"}}}


@pytest.mark.parametrize(
    ("path", "client"),
    [
        ("claude_desktop_config.json", McpClient.CLAUDE_DESKTOP),
        (".mcp.json", McpClient.CLAUDE_CODE),
        ("sub/.cursor/mcp.json", McpClient.CURSOR),
        (".copilot/mcp-config.json", McpClient.COPILOT),
        ("mcp.json", McpClient.UNKNOWN_CLIENT),
        ("examples/claude.json", McpClient.UNKNOWN_CLIENT),
    ],
)
def test_client_by_name_and_structure(path: str, client: McpClient) -> None:
    config = cfg(path, SERVERS)
    assert config is not None and config.client is client  # type: ignore[attr-defined]


def test_vscode_uses_servers_key_only_in_vscode_mcp_json() -> None:
    doc = {"servers": {"a": {"url": "http://mcp.example.com/mcp"}}}
    config = cfg(".vscode/mcp.json", doc)
    assert config is not None and config.servers_key == "servers"  # type: ignore[attr-defined]
    assert cfg("mcp.json", doc) is None
    assert cfg(".vscode/mcp.json", SERVERS) is None  # VS Code does not read mcpServers there


@pytest.mark.parametrize(
    "doc",
    [
        {"name": "mcp", "servers": ["http://x.example"]},
        {"mcpServers": []},
        {"mcpServers": {"a": "http://x.example"}},
        {"mcpServers": {"a": {"endpoint": "http://x.example"}}},
        {"mcpServers": {"a": {"url": 42}}},
        [{"mcpServers": {"a": {"url": "http://x.example"}}}],
        {"nested": {"mcpServers": {"a": {"url": "http://x.example"}}}},
    ],
)
def test_fake_metadata_is_not_an_mcp_config(doc: object) -> None:
    assert cfg(".mcp.json", doc) is None


def test_failed_or_python_modules_are_not_configs() -> None:
    assert recognise_config(parse_json_config(b"{", ".mcp.json")) is None
    assert recognise_config(parse_python(b"x = 1\n", "a.py")) is None


@pytest.mark.parametrize(
    ("entry", "transport"),
    [
        ({"command": "npx"}, Transport.STDIO),
        ({"url": "http://x.example"}, Transport.HTTP),
        ({"url": "http://x.example", "command": "x"}, Transport.STDIO),
        ({"type": "stdio", "url": "http://x.example"}, Transport.STDIO),
        ({"type": "streamableHttp", "url": "http://x.example"}, Transport.HTTP),
        ({"transport": "SSE", "url": "http://x.example"}, Transport.SSE),
        ({"type": "websocket", "url": "ws://x.example"}, Transport.UNKNOWN),
    ],
)
def test_transport_classification(entry: dict[str, str], transport: Transport) -> None:
    config = cfg(".mcp.json", {"mcpServers": {"s": entry}})
    assert config is not None and config.servers[0].transport is transport  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("extra", "auth"),
    [
        ({"headers": {"Authorization": "Bearer ${TOKEN}"}}, ("headers.Authorization",)),
        ({"headers": {"X-Custom": "${env:SECRET}"}}, ("headers.X-Custom",)),
        ({"headers": {"x-api-key": "literal"}}, ("headers.x-api-key",)),
        ({"headers": {"Authorization": ""}}, ()),
        ({"headers": {"Content-Type": "application/json"}}, ()),
        ({"headers": "Authorization: x"}, ()),
        ({"auth": {"CLIENT_ID": "${env:ID}"}}, ("auth",)),
        ({"oauth": {"clientId": "x"}}, ("oauth",)),
        ({"authorization_token": "${T}"}, ("authorization_token",)),
        ({"headersHelper": "./get-headers.sh"}, ("headersHelper",)),
        (
            {"requestInit": {"headers": {"Authorization": "Bearer ${T}"}}},
            ("requestInit.headers.Authorization",),
        ),
        ({"apiKey": None}, ()),
        ({"auth": {}}, ()),
        ({"useAuth": True}, ("useAuth",)),
        ({"useAuth": False}, ()),
        ({"tokenTtl": 3600}, ("tokenTtl",)),
        ({"env": {"API_TOKEN": "x"}}, ()),
    ],
)
def test_auth_indicators_are_names_only(extra: dict[str, object], auth: tuple[str, ...]) -> None:
    entry = {"url": "https://mcp.example.com/mcp", **extra}
    config = cfg(".mcp.json", {"mcpServers": {"s": entry}})
    assert config is not None
    server = config.servers[0]  # type: ignore[attr-defined]
    assert server.auth == auth
    assert "literal" not in repr(server.auth)


# --- rule: config ---------------------------------------------------------------------------------


def test_https_without_auth_is_medium_and_says_oauth_may_apply() -> None:
    [m] = matches(
        ".mcp.json", {"mcpServers": {"s": {"type": "http", "url": "https://h.example/m"}}}
    )
    assert (m.severity, m.confidence) == (Severity.MEDIUM, Confidence.MEDIUM)
    assert "No authentication setting (headers, auth block, bearer/OAuth)" in m.message
    assert "negotiate OAuth at connect time" in m.message
    assert m.message.startswith("The MCP server entry 's' in .mcp.json uses an HTTP transport at")


def test_private_https_without_auth_is_low() -> None:
    [m] = matches(".mcp.json", {"mcpServers": {"s": {"type": "http", "url": "https://mcp:8443/"}}})
    assert m.severity is Severity.LOW


def test_https_with_query_token_or_userinfo_is_not_reported() -> None:
    for url in ("https://h.example/m?access_token=abc", "https://u:p@h.example/m"):
        assert matches(".mcp.json", {"mcpServers": {"s": {"url": url}}}) == []


def test_non_http_schemes_are_ignored() -> None:
    for url in ("ftp://h.example/m", "file:///tmp/x", "ws://h.example/m"):
        assert matches(".mcp.json", {"mcpServers": {"s": {"type": "http", "url": url}}}) == []


def test_literal_secret_is_never_echoed(tmp_path: Path) -> None:
    secret = "sk-live-" + "Q" * 32
    doc = {
        "mcpServers": {
            "pay": {
                "type": "http",
                "url": "http://pay.example.com/mcp?api_key=" + secret,
                "headers": {"Authorization": "Bearer " + secret, "X-Api-Key": secret},
            }
        }
    }
    result = scan_virtual({".mcp.json": json.dumps(doc, indent=2).encode()}, tmp_path / "t")
    [finding] = result.findings
    assert "headers.Authorization" in finding.message
    terminal = render_scan(result, TerminalStyle(width=100))
    report = json.dumps(report_dict(result))
    for text in (terminal, report, repr(finding)):
        assert secret not in text and "QQQQQQQQ" not in text


def test_experimental_rule_is_off_by_default_and_says_so(tmp_path: Path) -> None:
    files = {".mcp.json": json.dumps(SERVERS).encode()}
    result = scan_virtual(files, tmp_path / "t", enable=())
    assert result.findings == () and result.exit_code == 0
    assert result.frameworks == ("MCP client config (1 file)",)
    assert any("NEX007 is experimental and not enabled" in n for n in result.completeness.notes)
    assert result.completeness.files_analysed == 1 and result.status.value == "complete"


def test_disable_via_config_and_exclude(tmp_path: Path) -> None:
    files = {
        ".mcp.json": json.dumps(SERVERS).encode(),
        ".nexvul.yml": b"rules:\n  enabled: [NEX007]\nexclude:\n  - .mcp.json\n",
    }
    result = scan_virtual(files, tmp_path / "a")
    assert result.findings == ()
    assert result.completeness.count(SkipReason.EXCLUDED_BY_CONFIG) == 1


def test_non_mcp_json_is_analysed_not_partial(tmp_path: Path) -> None:
    files = {"package.json": b'{"name": "x", "homepage": "http://example.com"}', "a.py": b"x = 1\n"}
    result = scan_virtual(files, tmp_path / "t")
    assert result.status.value == "complete" and result.completeness.files_analysed == 2
    assert result.findings == () and result.frameworks == ()
    assert dict(result.languages_analysed) == {"json": 1, "python": 1}


def test_fingerprint_is_stable_when_lines_move(tmp_path: Path) -> None:
    body = {"mcpServers": {"s": {"url": "http://mcp.example.com/mcp"}}}
    one = scan_virtual({".mcp.json": json.dumps(body).encode()}, tmp_path / "a")
    two = scan_virtual(
        {".mcp.json": ("\n\n" + json.dumps(body, indent=4)).encode()}, tmp_path / "b"
    )
    assert one.findings[0].fingerprint == two.findings[0].fingerprint
    assert one.findings[0].location.line != two.findings[0].location.line


# --- rule: Python --------------------------------------------------------------------------------

PY_HEAD = "from mcp.client.streamable_http import streamablehttp_client, streamable_http_client\n"


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ('streamablehttp_client("http://h.example/mcp")', (Severity.HIGH, Confidence.HIGH)),
        (
            'streamablehttp_client(url="https://h.example/mcp")',
            (Severity.MEDIUM, Confidence.MEDIUM),
        ),
        (
            'streamablehttp_client("https://h.example/mcp", headers=None)',
            (Severity.MEDIUM, Confidence.MEDIUM),
        ),
        ('streamablehttp_client("https://h.example/mcp", {"Authorization": t})', None),
        ('streamablehttp_client("https://h.example/mcp", auth=a)', None),
        ('streamable_http_client("https://h.example/mcp", http_client=c)', None),
        (
            'streamablehttp_client("http://h.example/mcp", headers=h)',
            (Severity.HIGH, Confidence.HIGH),
        ),
        ('streamablehttp_client("http://localhost:8000/mcp")', None),
        ('streamablehttp_client("http://10.0.0.2/mcp")', (Severity.MEDIUM, Confidence.HIGH)),
        ("streamablehttp_client(**kw)", None),
        ("streamablehttp_client(*args)", None),
        ('streamablehttp_client(f"http://{h}/mcp")', None),
        ("streamablehttp_client()", None),
        ('streamablehttp_client("not a url")', None),
        ('streamablehttp_client("ftp://h.example/")', None),
    ],
)
def test_python_client_calls(call: str, expected: tuple[Severity, Confidence] | None) -> None:
    found = py_matches(PY_HEAD + call + "\n")
    if expected is None:
        assert found == []
    else:
        [m] = found
        assert (m.severity, m.confidence) == expected
        assert "in this call's arguments" in m.message or "unencrypted" in m.message


def test_python_unresolved_or_shadowed_names_are_ignored() -> None:
    assert (
        py_matches(
            'def streamablehttp_client(u): ...\nstreamablehttp_client("http://h.example/")\n'
        )
        == []
    )
    assert py_matches('streamablehttp_client("http://h.example/")\n') == []
    assert list(find_http_client_calls(parse_python(b"def (:\n", "x.py"))) == []


def test_python_inline_suppression_applies(tmp_path: Path) -> None:
    src = (
        PY_HEAD + 'c = streamablehttp_client("http://h.example/mcp")'
        "  # nexvul: ignore[NEX007] -- internal test double behind the VPN\n"
    )
    result = scan_virtual({"a.py": src.encode()}, tmp_path / "t")
    assert result.findings == () and len(result.suppressed) == 1


# --- edge cases generated at test time (not committed) -------------------------------------------


def test_huge_config_over_the_size_cap_is_skipped_partial(tmp_path: Path) -> None:
    filler = {f"k{i}": "x" * 100 for i in range(12_000)}  # > 1 MiB
    doc = {"mcpServers": {"s": {"url": "http://mcp.example.com/mcp"}}, "pad": filler}
    files = {".mcp.json": json.dumps(doc).encode(), "a.py": b"x = 1\n"}
    result = scan_virtual(files, tmp_path / "t")
    assert result.findings == () and result.status.value == "partial"
    assert result.completeness.count(SkipReason.MAX_FILE_SIZE) == 1


def test_many_servers_are_capped_per_file(tmp_path: Path) -> None:
    doc = {"mcpServers": {f"s{i}": {"url": f"http://h{i}.example/mcp"} for i in range(150)}}
    result = scan_virtual({".mcp.json": json.dumps(doc).encode()}, tmp_path / "t")
    assert len(result.findings) == 100 and result.completeness.findings_truncated == 50
    assert result.status.value == "partial"


def test_deep_nesting_is_rejected_without_crashing(tmp_path: Path) -> None:
    deep = (
        '{"mcpServers": {"s": {"url": "http://h.example/"}}, "x": '
        + "[" * 5_000
        + "]" * 5_000
        + "}"
    )
    result = scan_virtual({".mcp.json": deep.encode()}, tmp_path / "t")
    assert result.findings == ()
    assert result.completeness.count(SkipReason.MAX_NESTING) == 1


def test_hostile_server_name_is_escaped_in_every_output(tmp_path: Path) -> None:
    name = ESC + "[2J" + chr(0x202E) + "x\nResult  0 findings"
    doc = {"mcpServers": {name: {"type": "http", "url": "http://h.example/mcp"}}}
    result = scan_virtual({".mcp.json": json.dumps(doc).encode()}, tmp_path / "t")
    [finding] = result.findings
    for text in (
        render_scan(result, TerminalStyle(width=100)),
        json.dumps(report_dict(result), ensure_ascii=False),
    ):
        assert ESC not in text and chr(0x202E) not in text
        assert not any(line.startswith("Result  0 findings") for line in text.splitlines())
    assert "\\x1b[2J" in finding.message


def test_worker_parses_json_in_process_task() -> None:
    reply = workers.handle_task(
        {
            "id": 3,
            "root": str(REPO / "tests" / "rules" / "nex007" / "positive"),
            "path": "case_001_cursor_http_no_auth/dot-cursor/mcp.json.fixture",
            "language": "json",
            "expect": None,
            "max_file_size": 1_000_000,
            "max_nesting": 100,
            "max_ast_nodes": 1000,
            "max_literal_chars": 1000,
            "max_result_bytes": 1_000_000,
        }
    )
    data = json.loads(reply)
    assert data["id"] == 3 and data["module"]["language"] == "json"
    assert data["module"]["config"]["syntax"] == "json"


def test_worker_reply_language_must_match_task() -> None:
    pool = workers._Pool(
        "/", workers.WorkerOptions(max_workers=1), workers.worker_main, lambda: 0.0
    )
    module = parse_json_config(b"{}", "a.json")
    from nexvul.ir.codec import module_to_json

    raw = b'{"id":0,"module":' + module_to_json(module) + b"}"
    assert pool._decode(workers._Task(0, "a.json", None, language="python"), raw) is None
    outcome = pool._decode(workers._Task(0, "a.json", None, language="json"), raw)
    assert outcome is not None and outcome.status is workers.OutcomeStatus.SCANNED


# --- explain / metadata ---------------------------------------------------------------------------


def test_metadata_matches_taxonomy_and_mapping() -> None:
    assert META.id == "NEX007" and META.asi == ("ASI07", "ASI04")
    assert META.cwe == ("CWE-319", "CWE-306")
    assert META.readiness.value == "experimental"
    assert META.doc is not None and "'claude mcp add'" in META.doc.not_detected


# --- goldens: one finding in terminal and JSON ----------------------------------------------------


def _normalise(result: ScanResult) -> ScanResult:
    tool = replace(result.tool, python="3.x", platform="test-platform", version="0.0.0-test")
    return replace(
        result,
        tool=tool,
        target="./mcp-demo",
        target_name="mcp-demo",
        started_at="2026-10-13T00:00:00+00:00",
        ended_at="2026-10-13T00:00:01+00:00",
        timings=(),
        completeness=replace(
            result.completeness,
            notes=tuple(n for n in result.completeness.notes if "memory" not in n),
        ),
    )


def _check(path: Path, text: str) -> None:
    if UPDATE:
        path.write_text(text, encoding="utf-8")
    assert path.exists(), f"missing golden {path}; run with NEXVUL_UPDATE_GOLDEN=1"
    assert text == path.read_text(encoding="utf-8")


def test_golden_terminal_and_json_for_one_finding(tmp_path: Path) -> None:
    doc = (
        '{\n  "mcpServers": {\n    "search": {\n      "type": "http",\n'
        '      "url": "http://mcp.example.com/mcp"\n    }\n  }\n}\n'
    )
    result = _normalise(scan_virtual({".cursor/mcp.json": doc.encode()}, tmp_path / "mcp-demo"))
    [finding] = result.findings
    assert finding.location.path == ".cursor/mcp.json" and finding.location.line == 5
    _check(
        GOLDEN / "terminal" / "NEX007-finding-100.txt",
        render_scan(result, TerminalStyle(width=100)),
    )
    _check(
        GOLDEN / "json" / "NEX007-finding.json",
        json.dumps(finding_to_dict(finding), indent=2, ensure_ascii=False) + "\n",
    )
