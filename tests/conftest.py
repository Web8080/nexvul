"""Shared test configuration.

* Fixture trees are data and are never collected (architecture §11.6). ``collect_ignore_glob``
  duplicates the ``norecursedirs`` setting in pyproject.toml as defence in depth.
* Every test runs with outbound network blocked (SR-23): any attempt to connect fails the test.
* ``canary_dir`` gives each test an empty directory exported as ``NEXVUL_CANARY_DIR``; hostile
  fixture payloads write there if they are ever executed, and tests assert it stays empty.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

collect_ignore_glob = [
    "fixtures/*",
    "rules/*",
    "security/fixtures/*",
    "../benchmarks/*",
]


class NetworkAccessError(AssertionError):
    pass


def _blocked(*_args: Any, **_kwargs: Any) -> Any:
    raise NetworkAccessError("network access attempted during tests (SR-23)")


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    original_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: Any) -> Any:
        if self.family == socket.AF_UNIX:
            return original_connect(self, address)
        return _blocked()

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    yield


@pytest.fixture
def canary_dir(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path_factory.mktemp("canary")
    monkeypatch.setenv("NEXVUL_CANARY_DIR", str(path))
    return path
