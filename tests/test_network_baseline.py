import json

import pytest

from src.network_baseline import (
    clear_baseline,
    compare_configuration,
    load_baseline,
    save_baseline,
)


def sample_scan(snapshot=None):
    return {
        "scan_id": "scan-123",
        "timestamp": "2026-10-30T12:00:00+00:00",
        "overall_status": "healthy",
        "configuration_snapshot": snapshot or {
            "adapter_name": "Ethernet",
            "ip_address": "192.168.1.25",
            "subnet_mask": "255.255.255.0",
            "default_gateway": "192.168.1.1",
            "dhcp_enabled": True,
            "dhcp_server": "192.168.1.1",
            "dns_servers": ["192.168.1.10"],
            "default_routes": [
                {"gateway": "192.168.1.1", "interface": "192.168.1.25", "metric": 25}
            ],
            "firewall_profiles": {"Domain": True, "Private": True, "Public": True},
            "tcp_target": {"host": "example.com", "port": 443},
            "tcp_result": "connected",
        },
    }


def test_load_baseline_returns_none_when_missing(tmp_path):
    assert load_baseline(tmp_path / "baseline.json") is None


def test_save_and_load_baseline(tmp_path):
    path = tmp_path / "baseline.json"
    scan = sample_scan()

    saved = save_baseline(scan, path)

    assert load_baseline(path) == saved
    assert saved["configuration_snapshot"] == scan["configuration_snapshot"]
    assert saved["source_scan_id"] == "scan-123"
    assert saved["saved_at"].endswith("+00:00")


def test_save_baseline_rejects_missing_snapshot(tmp_path):
    with pytest.raises(ValueError, match="configuration snapshot"):
        save_baseline({"results": []}, tmp_path / "baseline.json")


def test_compare_configuration_reports_configuration_drift():
    baseline = sample_scan()["configuration_snapshot"]
    current = {
        **baseline,
        "ip_address": "192.168.1.40",
        "default_gateway": "192.168.1.254",
        "dns_servers": ["8.8.8.8"],
        "firewall_profiles": {"Domain": True, "Private": False, "Public": True},
    }

    changes = compare_configuration(baseline, current)

    assert [change["field"] for change in changes] == [
        "ip_address",
        "default_gateway",
        "dns_servers",
        "firewall_profiles",
    ]
    assert changes[1]["assessment"] == "Review network path"
    assert changes[3]["assessment"] == "Review firewall configuration"


def test_compare_configuration_identifies_tcp_regression():
    baseline = sample_scan()["configuration_snapshot"]
    current = {**baseline, "tcp_result": "timeout"}

    changes = compare_configuration(baseline, current)

    assert len(changes) == 1
    assert changes[0]["field"] == "tcp_result"
    assert changes[0]["assessment"] == "Connectivity regression"


def test_compare_configuration_identifies_tcp_improvement():
    baseline = sample_scan()["configuration_snapshot"]
    baseline["tcp_result"] = "timeout"
    current = {**baseline, "tcp_result": "connected"}

    changes = compare_configuration(baseline, current)

    assert changes[0]["assessment"] == "Connectivity improvement"


def test_compare_configuration_does_not_compare_tcp_results_for_different_targets():
    baseline = sample_scan()["configuration_snapshot"]
    current = {
        **baseline,
        "tcp_target": {"host": "internal.example.com", "port": 443},
        "tcp_result": "timeout",
    }

    changes = compare_configuration(baseline, current)

    assert [change["field"] for change in changes] == ["tcp_target"]


def test_compare_configuration_ignores_unavailable_values():
    baseline = sample_scan()["configuration_snapshot"]
    current = {**baseline, "default_gateway": None, "dns_servers": None}

    assert compare_configuration(baseline, current) == []


def test_clear_baseline_removes_file(tmp_path):
    path = tmp_path / "baseline.json"
    save_baseline(sample_scan(), path)

    clear_baseline(path)

    assert load_baseline(path) is None
    assert not path.exists()


def test_baseline_file_is_valid_json(tmp_path):
    path = tmp_path / "baseline.json"
    save_baseline(sample_scan(), path)

    with path.open("r", encoding="utf-8") as baseline_file:
        assert isinstance(json.load(baseline_file), dict)
