import json
import subprocess
from types import SimpleNamespace

import pytest

from src.analyzers.firewall import analyze_firewall
from src.evidence_collection import collect_firewall_profiles


def test_firewall_analyzer_reports_all_profiles_enabled():
    result = analyze_firewall({
        "profiles": [
            {"name": "Domain", "enabled": True},
            {"name": "Private", "enabled": True},
            {"name": "Public", "enabled": True},
        ]
    })

    assert result["status"] == "healthy"
    assert len(result["evidence"]) == 3
    assert result["hypotheses"] == []


def test_firewall_analyzer_flags_disabled_profile_without_claiming_causation():
    result = analyze_firewall({
        "profiles": [
            {"name": "Domain", "enabled": True},
            {"name": "Private", "enabled": False},
            {"name": "Public", "enabled": True},
        ]
    })

    assert result["status"] == "investigate"
    assert "Private" in result["finding"]
    assert "does not establish whether it caused" in result["hypotheses"][0]["reason"]


def test_firewall_analyzer_returns_inconclusive_for_missing_profile():
    result = analyze_firewall({
        "profiles": [
            {"name": "Domain", "enabled": True},
            {"name": "Private", "enabled": True},
        ]
    })

    assert result["status"] == "inconclusive"
    assert "Public" in result["finding"]


def test_collect_firewall_profiles_parses_multiple_profiles(monkeypatch):
    output = json.dumps([
        {"Name": "Domain", "Enabled": True},
        {"Name": "Private", "Enabled": False},
        {"Name": "Public", "Enabled": True},
    ])
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output, stderr=""),
    )

    result = collect_firewall_profiles()

    assert result["source"] == "Windows Get-NetFirewallProfile"
    assert result["profiles"] == [
        {"name": "Domain", "enabled": True},
        {"name": "Private", "enabled": False},
        {"name": "Public", "enabled": True},
    ]


def test_collect_firewall_profiles_accepts_single_profile_json(monkeypatch):
    output = '{"Name":"Public","Enabled":true}'
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output, stderr=""),
    )

    result = collect_firewall_profiles()

    assert result["profiles"] == [{"name": "Public", "enabled": True}]


def test_collect_firewall_profiles_reports_command_failure(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="Access denied"),
    )

    with pytest.raises(RuntimeError, match="profile inspection failed"):
        collect_firewall_profiles()


def test_collect_firewall_profiles_reports_invalid_json(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="not json", stderr=""),
    )

    with pytest.raises(RuntimeError, match="invalid or empty JSON"):
        collect_firewall_profiles()


def test_collect_firewall_profiles_handles_timeout(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="powershell.exe", timeout=10)

    monkeypatch.setattr(subprocess, "run", timeout)

    with pytest.raises(RuntimeError, match="timed out"):
        collect_firewall_profiles()
