"""Regression coverage for HexStrike's health-tool detection."""

import builtins
import importlib
import importlib.metadata
import importlib.util
import zipfile
from types import SimpleNamespace

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


BUILTIN_CAPABILITY_CASES = (
    ("api-schema-analyzer", "/api/tools/api_schema_analyzer", "api_schema_analyzer"),
    ("graphql-scanner", "/api/tools/graphql_scanner", "graphql_scanner"),
    ("jwt-analyzer", "/api/tools/jwt_analyzer", "jwt_analyzer"),
)


def _patch_builtin_route_metadata(server, monkeypatch, path, endpoint, methods=("POST",), view_endpoint=None):
    rule = SimpleNamespace(rule=path, endpoint=endpoint, methods=set(methods))
    url_map = SimpleNamespace(iter_rules=lambda: iter((rule,)))
    monkeypatch.setattr(server.app, "url_map", url_map)
    monkeypatch.setattr(
        server.app,
        "view_functions",
        {view_endpoint or endpoint: lambda: None},
    )


@pytest.mark.parametrize("label, path, endpoint", BUILTIN_CAPABILITY_CASES)
def test_builtin_capability_is_available_for_registered_post_route(server, monkeypatch, label, path, endpoint):
    _patch_builtin_route_metadata(server, monkeypatch, path, endpoint)

    assert server._tool_is_available(label) is True


@pytest.mark.parametrize("label, path, endpoint", BUILTIN_CAPABILITY_CASES)
@pytest.mark.parametrize("missing", ["route", "function"])
def test_builtin_capability_is_unavailable_when_registration_is_incomplete(
    server, monkeypatch, label, path, endpoint, missing
):
    if missing == "route":
        monkeypatch.setattr(server.app, "url_map", SimpleNamespace(iter_rules=lambda: iter(())))
        monkeypatch.setattr(server.app, "view_functions", {endpoint: lambda: None})
    else:
        _patch_builtin_route_metadata(server, monkeypatch, path, endpoint, view_endpoint="other_endpoint")

    assert server._tool_is_available(label) is False


@pytest.mark.parametrize("label, path, endpoint", BUILTIN_CAPABILITY_CASES)
@pytest.mark.parametrize("mismatch", ["endpoint", "method"])
def test_builtin_capability_rejects_wrong_endpoint_or_missing_post(
    server, monkeypatch, label, path, endpoint, mismatch
):
    if mismatch == "endpoint":
        _patch_builtin_route_metadata(server, monkeypatch, path, "wrong_endpoint", view_endpoint=endpoint)
    else:
        _patch_builtin_route_metadata(server, monkeypatch, path, endpoint, methods=("GET",))

    assert server._tool_is_available(label) is False


@pytest.mark.parametrize("label, path, endpoint", BUILTIN_CAPABILITY_CASES)
def test_builtin_detection_reads_metadata_without_invoking_route(server, monkeypatch, label, path, endpoint):
    def forbidden_route_execution():
        raise AssertionError("built-in capability detection must not invoke routes")

    rule = SimpleNamespace(rule=path, endpoint=endpoint, methods={"POST"})
    monkeypatch.setattr(server.app, "url_map", SimpleNamespace(iter_rules=lambda: iter((rule,))))
    monkeypatch.setattr(server.app, "view_functions", {endpoint: forbidden_route_execution})

    assert server._tool_is_available(label) is True


def test_python_package_detection_accepts_import_discoverable_angr(server, monkeypatch):
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name: object() if name == "angr" else None,
    )
    def package_version(name):
        if name == "angr":
            return "9.2.120"
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", package_version)

    assert server._tool_is_available("angr") is True


def test_python_package_detection_rejects_missing_angr_module(server, monkeypatch):
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "9.2.120")

    assert server._tool_is_available("angr") is False


def test_python_package_detection_rejects_missing_angr_metadata(server, monkeypatch):
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name: object() if name == "angr" else None,
    )

    def missing_metadata(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing_metadata)

    assert server._tool_is_available("angr") is False


def test_health_detects_angr_without_importing_or_executing_package(server, monkeypatch):
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name: object() if name == "angr" else None,
    )
    real_version = importlib.metadata.version

    def package_version(name):
        return "9.2.120" if name == "angr" else real_version(name)

    monkeypatch.setattr(importlib.metadata, "version", package_version)
    real_import = builtins.__import__

    def reject_angr_import(name, *args, **kwargs):
        if name == "angr" or name.startswith("angr."):
            raise AssertionError("health detection must not import angr")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_angr_import)
    payload = server.app.test_client().get("/health").get_json()

    assert payload["tools_status"]["angr"] is True


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


FALCO_SENTINEL = "/home/hexstrike/.local/falco-0.44.1-x86_64/usr/bin/falco"


def test_falco_detection_uses_explicit_sentinel_when_not_on_path(server):
    def checker(path):
        return path == FALCO_SENTINEL

    assert server._tool_is_available(
        "falco",
        executable_finder=lambda name: None,
        executable_file_checker=checker,
    ) is True


def test_falco_detection_fails_closed_for_missing_sentinel(server, monkeypatch, tmp_path):
    missing = tmp_path / "falco"
    monkeypatch.setattr(server, "TOOL_PATH_SENTINELS", {"falco": (str(missing),)})

    assert server._tool_is_available(
        "falco",
        executable_finder=lambda name: None,
    ) is False


def test_falco_detection_fails_closed_for_non_executable_sentinel(server, monkeypatch, tmp_path):
    non_executable = tmp_path / "falco"
    non_executable.write_text("not executable", encoding="utf-8")
    non_executable.chmod(0o644)
    monkeypatch.setattr(server, "TOOL_PATH_SENTINELS", {"falco": (str(non_executable),)})

    assert server._tool_is_available(
        "falco",
        executable_finder=lambda name: None,
    ) is False


def test_falco_detection_fails_closed_for_directory_sentinel(server, monkeypatch, tmp_path):
    sentinel_directory = tmp_path / "falco"
    sentinel_directory.mkdir()
    monkeypatch.setattr(server, "TOOL_PATH_SENTINELS", {"falco": (str(sentinel_directory),)})

    assert server._tool_is_available(
        "falco",
        executable_finder=lambda name: None,
    ) is False


def test_falco_sentinel_rejects_symlink(server, monkeypatch, tmp_path):
    target = tmp_path / "falco-target"
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o755)
    symlink = tmp_path / "falco"
    symlink.symlink_to(target)
    monkeypatch.setattr(server, "TOOL_PATH_SENTINELS", {"falco": (str(symlink),)})

    assert server._tool_is_available(
        "falco",
        executable_finder=lambda name: None,
    ) is False


def test_falco_path_detection_remains_a_valid_fallback(server):
    path_entry = "/tmp/falco-from-path"

    assert server._tool_is_available(
        "falco",
        executable_finder=lambda name: path_entry,
        executable_file_checker=lambda path: path == path_entry,
    ) is True


def test_libc_database_path_sentinel_does_not_gain_path_fallback(server):
    path_entry = "/tmp/libc-database-from-path"

    assert server._tool_is_available(
        "libc-database",
        executable_finder=lambda name: path_entry,
        executable_file_checker=lambda path: path == path_entry,
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


def test_hibp_detection_requires_registered_integration_not_a_path(server, monkeypatch):
    key = "a" * 32
    monkeypatch.setenv("HIBP_API_KEY", key)
    monkeypatch.setattr(server, "_hibp_is_verified", lambda value: value == key)

    assert server._tool_is_available(
        "have-i-been-pwned",
        executable_finder=lambda name: "/tmp/fake-executable",
        executable_file_checker=lambda path: True,
    ) is True

    monkeypatch.setattr(server.app, "url_map", SimpleNamespace(iter_rules=lambda: iter(())))
    assert server._tool_is_available(
        "have-i-been-pwned",
        executable_finder=lambda name: "/tmp/fake-executable",
        executable_file_checker=lambda path: True,
    ) is False


def test_hibp_detection_requires_a_registered_client(server, monkeypatch):
    monkeypatch.setattr(server, "HIBPClient", None)

    assert server._tool_is_available(
        "have-i-been-pwned",
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
