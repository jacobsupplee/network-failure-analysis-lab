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
