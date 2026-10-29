import json
from pathlib import Path

import pytest

from src.analysis_runner import run_analysis


def test_run_analysis_on_apipa_scenario():
    scenario_path = (
        Path(__file__).parent.parent
        / "scenarios"
        / "apipa_dhcp.json"
    )

    result = run_analysis(scenario_path)

    assert result["scenario_id"] == "DHCP-001"
    assert result["analysis"]["status"] == "investigate"
    assert result["matches_expected"] is True


def test_run_analysis_on_dns_failure():
    scenario_path = (
        Path(__file__).parent.parent
        / "scenarios"
        / "dns_failure.json"
    )

    result = run_analysis(scenario_path)

    assert result["scenario_id"] == "DNS-001"
    assert result["diagnostic_type"] == "dns"
    assert result["analysis"]["status"] == "investigate"
    assert result["matches_expected"] is True


def test_run_analysis_on_refused_tcp_port(tmp_path):
    scenario = {
        "scenario_id": "TCP-001",
        "diagnostic_type": "ports",
        "title": "Web service refuses TCP connections",
        "description": "A target host is reachable, but its HTTPS port refuses connections.",
        "evidence": {
            "host": "192.0.2.10",
            "port": 443,
            "result": "refused",
            "error": "Connection refused",
        },
        "expected_status": "investigate",
    }
    scenario_path = tmp_path / "tcp_port_refused.json"
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")

    result = run_analysis(scenario_path)

    assert result["scenario_id"] == "TCP-001"
    assert result["diagnostic_type"] == "ports"
    assert result["analysis"]["status"] == "investigate"
    assert result["analysis"]["hypotheses"][0]["cause"] == (
        "Service unavailable or connection actively rejected"
    )
    assert result["matches_expected"] is True

def test_run_analysis_on_unavailable_dns_lookup(tmp_path):
    scenario = {
        "scenario_id": "DNS-002",
        "diagnostic_type": "dns",
        "title": "DNS lookup utility is unavailable",
        "description": "The DNS test could not run because the lookup utility was unavailable.",
        "evidence": {
            "hostname": "example.com",
            "dns_server": "192.0.2.53",
            "resolution_result": "unavailable",
        },
        "expected_status": "inconclusive",
    }
    scenario_path = tmp_path / "dns_unavailable.json"
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")

    result = run_analysis(scenario_path)

    assert result["scenario_id"] == "DNS-002"
    assert result["diagnostic_type"] == "dns"
    assert result["analysis"]["status"] == "inconclusive"
    assert result["analysis"]["hypotheses"] == []
    assert result["matches_expected"] is True

def test_run_analysis_on_missing_default_route(tmp_path):
    scenario = {
        "scenario_id": "ROUTE-001",
        "diagnostic_type": "routing",
        "title": "Default route is missing",
        "description": "The routing table contains a local network route but no default route.",
        "evidence": {
            "destination": "1.1.1.1",
            "default_gateway": "192.168.1.1",
            "routes": [
                {
                    "destination": "192.168.1.0",
                    "netmask": "255.255.255.0",
                    "gateway": "0.0.0.0",
                    "interface": "192.168.1.25",
                    "metric": 25,
                }
            ],
        },
        "expected_status": "investigate",
    }
    scenario_path = tmp_path / "missing_default_route.json"
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")

    result = run_analysis(scenario_path)

    assert result["scenario_id"] == "ROUTE-001"
    assert result["diagnostic_type"] == "routing"
    assert result["analysis"]["status"] == "investigate"
    assert result["analysis"]["hypotheses"][0]["cause"] == (
        "Missing IPv4 default route"
    )
    assert result["matches_expected"] is True

def test_run_analysis_on_default_gateway_mismatch(tmp_path):
    scenario = {
        "scenario_id": "ROUTE-002",
        "diagnostic_type": "routing",
        "title": "Reported gateway does not match default route",
        "description": "The configured gateway differs from the gateway recorded in the default route.",
        "evidence": {
            "destination": "1.1.1.1",
            "default_gateway": "192.168.1.254",
            "routes": [
                {
                    "destination": "0.0.0.0",
                    "netmask": "0.0.0.0",
                    "gateway": "192.168.1.1",
                    "interface": "192.168.1.25",
                    "metric": 25,
                }
            ],
        },
        "expected_status": "investigate",
    }
    scenario_path = tmp_path / "default_gateway_mismatch.json"
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")

    result = run_analysis(scenario_path)

    assert result["scenario_id"] == "ROUTE-002"
    assert result["diagnostic_type"] == "routing"
    assert result["analysis"]["status"] == "investigate"
    assert result["analysis"]["hypotheses"][0]["cause"] == (
        "Default gateway mismatch"
    )
    assert result["matches_expected"] is True



def test_run_analysis_on_valid_default_route(tmp_path):
    scenario = {
        "scenario_id": "ROUTE-003",
        "diagnostic_type": "routing",
        "title": "Default route is available",
        "description": "The routing table contains a valid IPv4 default route.",
        "evidence": {
            "destination": "1.1.1.1",
            "default_gateway": "192.168.1.1",
            "routes": [
                {
                    "destination": "0.0.0.0",
                    "netmask": "0.0.0.0",
                    "gateway": "192.168.1.1",
                    "interface": "192.168.1.25",
                    "metric": 25,
                }
            ],
        },
        "expected_status": "route_present",
    }
    scenario_path = tmp_path / "valid_default_route.json"
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")

    result = run_analysis(scenario_path)

    assert result["scenario_id"] == "ROUTE-003"
    assert result["diagnostic_type"] == "routing"
    assert result["analysis"]["status"] == "route_present"
    assert result["analysis"]["hypotheses"] == []
    assert result["matches_expected"] is True


def test_run_analysis_rejects_incomplete_scenario(tmp_path):
    scenario = {
        "scenario_id": "INVALID-001",
        "diagnostic_type": "dns",
    }
    scenario_path = tmp_path / "incomplete_scenario.json"
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")

    with pytest.raises(ValueError, match="Scenario is missing required fields"):
        run_analysis(scenario_path)



def test_run_analysis_rejects_malformed_json(tmp_path):
    scenario_path = tmp_path / "malformed_scenario.json"
    scenario_path.write_text('{"scenario_id": "INVALID-002",', encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        run_analysis(scenario_path)


def test_run_analysis_rejects_non_object_json(tmp_path):
    scenario_path = tmp_path / "scenario_array.json"
    scenario_path.write_text('[{"scenario_id": "INVALID-003"}]', encoding="utf-8")

    with pytest.raises(ValueError, match="Scenario must be a JSON object"):
        run_analysis(scenario_path)
