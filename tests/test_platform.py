"""Tests for platform helpers (tool lookup, subprocess safety)."""

import subprocess

from src.utils.platform import find_tool, run_subprocess


def test_find_tool_missing_returns_none():
    # A name that cannot exist on any OS.
    assert find_tool("definitely-not-a-real-tool-xyz") is None


def test_find_tool_tries_kali_alias_first(monkeypatch):
    tried = []

    def fake_which(name):
        tried.append(name)
        return "C:/fake/httpx-toolkit.exe" if name == "httpx-toolkit" else None

    monkeypatch.setattr("src.utils.platform.shutil.which", fake_which)
    assert find_tool("httpx") == "C:/fake/httpx-toolkit.exe"
    assert tried[0] == "httpx-toolkit"  # Kali alias checked before plain httpx


def test_run_subprocess_uses_list_args_and_timeout(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr("src.utils.platform.subprocess.run", fake_run)
    proc = run_subprocess(["tool", "-d", "example.com"], timeout=5)
    assert proc.stdout == b"ok"
    assert captured["cmd"] == ["tool", "-d", "example.com"]  # list args, no shell
    assert captured["shell"] is False
    assert captured["timeout"] == 5


def test_run_subprocess_converts_timeout(monkeypatch):
    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="x", timeout=0.1)

    monkeypatch.setattr("src.utils.platform.subprocess.run", boom)
    try:
        run_subprocess(["any"], timeout=0.1)
    except TimeoutError:
        pass  # normalized TimeoutError — expected
    else:
        raise AssertionError("Expected TimeoutError")
