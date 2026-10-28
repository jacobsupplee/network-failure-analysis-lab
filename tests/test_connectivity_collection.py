import subprocess
from types import SimpleNamespace

from src.evidence_collection import collect_connectivity


def test_connectivity_when_both_targets_respond(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="Reply from target",
            stderr="",
        ),
    )

    result = collect_connectivity("192.168.1.1")

    assert result["gateway_reachable"] is True
    assert result["external_reachable"] is True


def test_connectivity_when_ping_fails(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="Request timed out.",
            stderr="",
        ),
    )

    result = collect_connectivity("192.168.1.1")

    assert result["gateway_reachable"] is False
    assert result["external_reachable"] is False


def test_connectivity_handles_command_timeout(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="ping", timeout=5)

    monkeypatch.setattr(subprocess, "run", timeout)

    result = collect_connectivity("192.168.1.1")

    assert result["gateway_reachable"] is None
    assert result["external_reachable"] is None


def test_connectivity_without_gateway(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="Reply from target",
            stderr="",
        ),
    )

    result = collect_connectivity(None)

    assert result["gateway_reachable"] is None
    assert result["external_reachable"] is True

def test_connectivity_handles_missing_ping_command(monkeypatch):
    def command_missing(*args, **kwargs):
        raise FileNotFoundError("ping not found")

    monkeypatch.setattr(subprocess, "run", command_missing)

    result = collect_connectivity("192.168.1.1")

    assert result["gateway_reachable"] is None
    assert result["external_reachable"] is None

