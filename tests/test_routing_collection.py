import subprocess
import pytest

from src.evidence_collection import collect_routing_table

def test_collect_routing_table_parses_default_route(monkeypatch):
    output = """===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       192.168.1.1    192.168.1.100     25
        192.168.1.0    255.255.255.0        On-link     192.168.1.100    281
Persistent Routes:
  None
"""

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0],
            0,
            stdout=output,
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    report = collect_routing_table()

    assert report["source"] == "Windows route print -4"
    assert len(report["routes"]) == 2
    assert report["routes"][0]["destination"] == "0.0.0.0"
    assert report["routes"][0]["gateway"] == "192.168.1.1"
    assert report["routes"][0]["metric"] == 25

def test_collect_routing_table_ignores_persistent_routes(monkeypatch):
    output = """IPv4 Route Table
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
Persistent Routes:
Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0       192.168.1.1    192.168.1.100     25
"""

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0],
            0,
            stdout=output,
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    report = collect_routing_table()

    assert report["routes"] == []

def test_collect_routing_table_raises_on_command_failure(monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0],
            1,
            stdout="",
            stderr="Access denied",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="route print failed"):
        collect_routing_table()

def test_collect_routing_table_raises_on_timeout(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 10)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="timed out"):
        collect_routing_table()