import json
from pathlib import Path

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

