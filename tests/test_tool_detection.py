"""Regression coverage for HexStrike's health-tool detection."""

import importlib
import zipfile

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


def _write_stegsolve_jar(path, main_class="stegsolve.StegSolve"):
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr(
            "META-INF/MANIFEST.MF",
            f"Manifest-Version: 1.0\nMain-Class: {main_class}\n",
        )


def test_health_detects_valid_stegsolve_jar(server, monkeypatch, tmp_path):
    jar = tmp_path / "stegsolve.jar"
    _write_stegsolve_jar(jar)
    monkeypatch.setattr(
        server,
        "TOOL_JAR_SENTINELS",
        {"stegsolve": ((str(jar), "stegsolve.StegSolve"),)},
        raising=False,
    )

    assert server._tool_is_available("stegsolve") is True


def _corrupt_compressed_manifest(path):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as jar:
        jar.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\nMain-Class: stegsolve.StegSolve\n" + "X" * 5000,
        )
    raw = bytearray(path.read_bytes())
    with zipfile.ZipFile(path) as jar:
        info = jar.getinfo("META-INF/MANIFEST.MF")
    name_length = int.from_bytes(raw[info.header_offset + 26:info.header_offset + 28], "little")
    extra_length = int.from_bytes(raw[info.header_offset + 28:info.header_offset + 30], "little")
    data_start = info.header_offset + 30 + name_length + extra_length
    raw[data_start + max(1, info.compress_size // 2)] ^= 0xFF
    path.write_bytes(raw)


def test_stegsolve_jar_sentinel_rejects_corrupt_compressed_manifest(server, monkeypatch, tmp_path):
    jar = tmp_path / "corrupt.jar"
    _corrupt_compressed_manifest(jar)
    monkeypatch.setattr(
        server,
        "TOOL_JAR_SENTINELS",
        {"stegsolve": ((str(jar), "stegsolve.StegSolve"),)},
        raising=False,
    )

    assert server._tool_is_available("stegsolve") is False


def test_stegsolve_jar_sentinel_ignores_named_manifest_sections(server, monkeypatch, tmp_path):
    jar = tmp_path / "section.jar"
    with zipfile.ZipFile(jar, "w") as archive:
        archive.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\n\nName: fake\nMain-Class: stegsolve.StegSolve\n",
        )
    monkeypatch.setattr(
        server,
        "TOOL_JAR_SENTINELS",
        {"stegsolve": ((str(jar), "stegsolve.StegSolve"),)},
        raising=False,
    )

    assert server._tool_is_available("stegsolve") is False


@pytest.mark.parametrize("fixture", ["missing", "directory", "invalid", "wrong-main", "symlink"])
def test_stegsolve_jar_sentinel_rejects_invalid_paths(server, monkeypatch, tmp_path, fixture):
    jar = tmp_path / "stegsolve.jar"
    if fixture == "directory":
        jar.mkdir()
    elif fixture == "invalid":
        jar.write_text("not a jar", encoding="utf-8")
    elif fixture == "wrong-main":
        _write_stegsolve_jar(jar, main_class="other.Main")
    elif fixture == "symlink":
        target = tmp_path / "target.jar"
        _write_stegsolve_jar(target)
        jar.symlink_to(target)
    monkeypatch.setattr(
        server,
        "TOOL_JAR_SENTINELS",
        {"stegsolve": ((str(jar), "stegsolve.StegSolve"),)},
        raising=False,
    )

    assert server._tool_is_available("stegsolve") is False


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
    ["hashpump", "outguess", "terrascan", "falco"],
)
def test_genuinely_unavailable_tools_remain_unavailable(server, monkeypatch, label):
    assert server._tool_is_available(
        label,
        executable_finder=lambda name: None,
        executable_file_checker=lambda path: False,
    ) is False
