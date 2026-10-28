import subprocess
from types import SimpleNamespace
import pytest

from src.evidence_collection import (
    collect_dns_resolution,
    collect_network_configuration,
)

def test_collect_network_configuration_parses_adapter(monkeypatch):
    output = """Windows IP Configuration

Ethernet adapter Ethernet:
   DHCP Enabled. . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . : 192.168.1.25(Preferred)
   Subnet Mask . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . : 192.168.1.1
   DHCP Server . . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . : 192.168.1.1
                                       1.1.1.1
"""
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=output,
            stderr="",
        ),
    )

    result = collect_network_configuration()

    adapter = result["primary_adapter"]

    assert adapter["name"] == "Ethernet"
    assert adapter["ip_address"] == "192.168.1.25"
    assert adapter["subnet_mask"] == "255.255.255.0"
    assert adapter["default_gateway"] == "192.168.1.1"
    assert adapter["dhcp_enabled"] is True
    assert adapter["dhcp_server"] == "192.168.1.1"
    assert adapter["dns_servers"] == ["192.168.1.1", "1.1.1.1"]
    assert result["raw_output"] == output

def test_collect_network_configuration_handles_no_adapters(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="Windows IP Configuration\n",
            stderr="",
        ),
    )

    result = collect_network_configuration()

    assert result["adapters"] == []
    assert result["primary_adapter"] is None

def test_collect_network_configuration_raises_on_command_failure(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="Access denied",
        ),
    )

    with pytest.raises(RuntimeError, match="ipconfig failed"):
        collect_network_configuration()

def test_collect_dns_resolution_success(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="Name: example.com\nAddress: 93.184.216.34",
            stderr="",
        ),
    )

    result = collect_dns_resolution("example.com")

    assert result["hostname"] == "example.com"
    assert result["resolution_result"] == "success"

def test_collect_dns_resolution_nxdomain(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="*** server can't find nonexistent.invalid: Non-existent domain",
        ),
    )

    result = collect_dns_resolution("nonexistent.invalid")

    assert result["resolution_result"] == "nxdomain"

def test_collect_dns_resolution_timeout(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="nslookup", timeout=10)

    monkeypatch.setattr(subprocess, "run", timeout)

    result = collect_dns_resolution("example.com")

    assert result["hostname"] == "example.com"
    assert result["resolution_result"] == "timeout"
