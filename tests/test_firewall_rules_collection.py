import json
import socket
import subprocess
from types import SimpleNamespace

import pytest

from src.evidence_collection import collect_firewall_rules


def mock_command(monkeypatch, *, stdout="", stderr="", returncode=0):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
        ),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        lambda host: "203.0.113.8",
    )


def test_collect_firewall_rules_normalizes_rule_records(monkeypatch):
    mock_command(
        monkeypatch,
        stdout=json.dumps([
            {
                "DisplayName": "Block HTTPS",
                "Action": "Block",
                "Profile": "Private, Public",
                "Protocol": "TCP",
                "LocalPort": "Any",
                "RemotePort": "443,8443",
                "LocalAddress": "*",
                "RemoteAddress": "203.0.113.0/24",
                "Program": "Any",
                "Service": "Any",
            }
        ]),
    )

    result = collect_firewall_rules(" example.com ", 443)

    assert result["target_host"] == "example.com"
    assert result["target_ip"] == "203.0.113.8"
    assert result["target_port"] == 443
    assert result["source"] == "Windows Get-NetFirewallRule ActiveStore outbound rules"
    assert result["candidate_rules"] == [
        {
            "display_name": "Block HTTPS",
            "action": "block",
            "profile": "Private, Public",
            "protocol": "TCP",
            "local_port": "Any",
            "remote_port": "443,8443",
            "local_address": "*",
            "remote_address": "203.0.113.0/24",
            "program": "Any",
            "service": "Any",
        }
    ]


def test_collect_firewall_rules_accepts_single_rule_object(monkeypatch):
    mock_command(
        monkeypatch,
        stdout=json.dumps({"DisplayName": "Block DNS", "Action": "Block"}),
    )

    result = collect_firewall_rules("203.0.113.8", 53)

    assert len(result["candidate_rules"]) == 1
    assert result["candidate_rules"][0]["display_name"] == "Block DNS"
    assert result["candidate_rules"][0]["action"] == "block"
    assert result["candidate_rules"][0]["protocol"] == "Any"


def test_collect_firewall_rules_empty_output_returns_no_candidates(monkeypatch):
    mock_command(monkeypatch, stdout="")

    result = collect_firewall_rules("example.com", 443)

    assert result["candidate_rules"] == []
    assert result["raw_output"] == ""


def test_collect_firewall_rules_ignores_non_object_records(monkeypatch):
    mock_command(monkeypatch, stdout=json.dumps([None, "bad record", {"DisplayName": "Rule"}]))

    result = collect_firewall_rules("example.com", 443)

    assert len(result["candidate_rules"]) == 1
    assert result["candidate_rules"][0]["display_name"] == "Rule"


@pytest.mark.parametrize(
    ("host", "port"),
    [
        ("", 443),
        ("   ", 443),
        ("example.com", 0),
        ("example.com", 65536),
        ("example.com", True),
        (123, 443),
    ],
)
def test_collect_firewall_rules_rejects_invalid_target(host, port):
    with pytest.raises(ValueError):
        collect_firewall_rules(host, port)


def test_collect_firewall_rules_uses_hostname_when_resolution_fails(monkeypatch):
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        lambda host: (_ for _ in ()).throw(socket.gaierror("DNS unavailable")),
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="", stderr="", returncode=0),
    )

    result = collect_firewall_rules("unresolvable.invalid", 443)

    assert result["target_ip"] == "unresolvable.invalid"
    assert result["candidate_rules"] == []


def test_collect_firewall_rules_reports_timeout(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname", lambda host: "203.0.113.8")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="powershell.exe", timeout=15)

    monkeypatch.setattr(subprocess, "run", timeout)

    with pytest.raises(RuntimeError, match="timed out"):
        collect_firewall_rules("example.com", 443)


def test_collect_firewall_rules_reports_missing_powershell(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname", lambda host: "203.0.113.8")

    def missing_command(*args, **kwargs):
        raise FileNotFoundError("powershell.exe not found")

    monkeypatch.setattr(subprocess, "run", missing_command)

    with pytest.raises(RuntimeError, match="Could not run PowerShell"):
        collect_firewall_rules("example.com", 443)


def test_collect_firewall_rules_reports_command_failure(monkeypatch):
    mock_command(monkeypatch, returncode=1, stderr="Access denied")

    with pytest.raises(RuntimeError, match="inspection failed: Access denied"):
        collect_firewall_rules("example.com", 443)


def test_collect_firewall_rules_reports_invalid_json(monkeypatch):
    mock_command(monkeypatch, stdout="not-json")

    with pytest.raises(RuntimeError, match="invalid rule JSON"):
        collect_firewall_rules("example.com", 443)


@pytest.mark.parametrize("payload", ['"unexpected"', "null", "42"])
def test_collect_firewall_rules_rejects_invalid_collection_type(monkeypatch, payload):
    mock_command(monkeypatch, stdout=payload)

    with pytest.raises(RuntimeError, match="invalid rule collection"):
        collect_firewall_rules("example.com", 443)
