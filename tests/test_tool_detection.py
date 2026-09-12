"""Regression coverage for HexStrike's health-tool detection."""

import importlib

import pytest


@pytest.fixture()
def server(monkeypatch):
    module = importlib.import_module("hexstrike_server")
    monkeypatch.setattr(module.cache, "get", lambda *args, **kwargs: None)
    monkeypatch.setattr(module.cache, "set", lambda *args, **kwargs: None)
    return module


def _health_payload(server, monkeypatch, detector):
    monkeypatch.setattr(server, "_tool_is_available", detector)
    return server.app.test_client().get("/health").get_json()


def test_health_detects_installed_executable_aliases(server):
    available = {
        "bulk_extractor", "censys", "searchsploit", "one_gadget", "pwn",
        "ROPgadget", "scout", "shodan", "vol",
    }
    finder = lambda name: f"/tmp/hexstrike-{name}" if name in available else None
    checker = lambda path: path.startswith("/tmp/hexstrike-")

    for label in (
        "bulk-extractor", "censys-cli", "exploit-db", "one-gadget", "pwntools",
        "ropgadget", "scout-suite", "shodan-cli", "volatility3",
    ):
        assert server._tool_is_available(
            label,
            executable_finder=finder,
            executable_file_checker=checker,
        ) is True

    # Volatility 3 must not be reported as Volatility 2 compatibility.
    assert server._tool_is_available(
        "volatility",
        executable_finder=finder,
        executable_file_checker=checker,
    ) is False


def test_health_detects_suite_sentinels_and_libc_database(server):
    finder = lambda name: f"/tmp/hexstrike-{name}" if name in {"msfconsole", "fls"} else None
    executables = {"/opt/libc-database/find"}
    checker = lambda path: path.startswith("/tmp/hexstrike-")

    assert server._tool_is_available(
        "metasploit", executable_finder=finder, executable_file_checker=checker
    ) is True
    assert server._tool_is_available(
        "sleuthkit", executable_finder=finder, executable_file_checker=checker
    ) is True
    assert server._tool_is_available(
        "hashcat-utils",
        executable_file_checker=lambda path: path == "/usr/lib/hashcat-utils/cap2hccapx.bin",
    ) is True
    assert server._tool_is_available("libc-database", executable_file_checker=executables.__contains__) is True


def test_ctf_command_mappings_use_verified_entrypoints(server):
    manager = server.CTFToolManager()

    assert manager.tool_commands["libc-database"] == "/opt/libc-database/find"
    assert manager.tool_commands["volatility3"] == "vol -f"


def test_health_counts_one_label_per_canonical_capability(server, monkeypatch):
    calls = []
    payload = _health_payload(server, monkeypatch, lambda label: calls.append(label) or False)

    assert payload["total_tools_count"] == len(calls)
    assert {"vol", "searchsploit", "msfconsole", "msfvenom"}.isdisjoint(calls)
    assert {"volatility3", "exploit-db", "metasploit"}.issubset(calls)


def test_canonical_deduplication_is_order_independent(server):
    categories = server._dedupe_tool_categories({
        "test": ["vol", "volatility3", "searchsploit", "exploit-db", "msfconsole", "metasploit"],
    })

    assert categories["test"] == ["volatility3", "exploit-db", "metasploit"]


def test_executable_sentinel_rejects_non_executable_files_and_symlinks(server, tmp_path):
    executable = tmp_path / "sentinel"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    non_executable = tmp_path / "non-executable"
    non_executable.write_text("data", encoding="utf-8")
    non_executable.chmod(0o644)
    symlink = tmp_path / "symlink"
    symlink.symlink_to(executable)

    assert server._is_executable_file(str(executable)) is True
    assert server._is_executable_file(str(non_executable)) is False
    assert server._is_executable_file(str(symlink)) is False


def test_path_detection_validates_realpath_target(server, tmp_path):
    executable = tmp_path / "pipx-entrypoint"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    executable_link = tmp_path / "entrypoint-link"
    executable_link.symlink_to(executable)
    non_executable = tmp_path / "non-executable-target"
    non_executable.write_text("data", encoding="utf-8")
    non_executable.chmod(0o644)
    invalid_link = tmp_path / "invalid-link"
    invalid_link.symlink_to(non_executable)

    assert server._tool_is_available(
        "pwn",
        executable_finder=lambda name: str(executable_link),
    ) is True
    assert server._tool_is_available(
        "pwn",
        executable_finder=lambda name: str(invalid_link),
    ) is False


def test_hashcat_utils_requires_an_executable_sentinel(server):
    assert server._tool_is_available(
        "hashcat-utils",
        executable_file_checker=lambda path: False,
    ) is False


@pytest.mark.parametrize(
    "label",
    ["api-schema-analyzer", "graphql-scanner", "have-i-been-pwned", "jwt-analyzer"],
)
def test_conceptual_labels_remain_unavailable(server, label):
    assert server._tool_is_available(
        label,
        executable_finder=lambda name: "/tmp/fake-executable",
        executable_file_checker=lambda path: True,
    ) is False


def test_health_totals_and_labels_are_unique(server, monkeypatch):
    payload = _health_payload(server, monkeypatch, lambda label: False)

    assert payload["total_tools_count"] == len(payload["tools_status"])
    assert list(payload["tools_status"]).count("paramspider") == 1
    assert list(payload["tools_status"]).count("graphql-scanner") == 1
    assert list(payload["tools_status"]).count("jwt-analyzer") == 1


@pytest.mark.parametrize(
    "label",
    ["hashpump", "outguess", "terrascan", "falco", "stegsolve"],
)
def test_genuinely_unavailable_tools_remain_unavailable(server, monkeypatch, label):
    assert server._tool_is_available(
        label,
        executable_finder=lambda name: None,
        executable_file_checker=lambda path: False,
    ) is False
