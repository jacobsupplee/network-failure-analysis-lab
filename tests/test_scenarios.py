import pytest
import json

from src.scenario_loader import load_scenario

def test_load_valid_scenario(tmp_path):
    scenario_data = {
        "scenario_id": "DHCP-001",
        "diagnostic_type": "dhcp",
        "title": "APIPA address",
        "evidence": {
            "ip_address": "169.254.12.34",
            "default_gateway": None,
            "dhcp_server": None,
        },
        "expected_status": "investigate",
    }

    scenario_file = tmp_path / "scenario.json"
    scenario_file.write_text(json.dumps(scenario_data), encoding="utf-8")

    result = load_scenario(scenario_file)

    assert result["scenario_id"] == "DHCP-001"
    assert result["evidence"]["ip_address"] == "169.254.12.34"
    assert result["diagnostic_type"] == "dhcp"

def test_reject_scenario_missing_required_fields(tmp_path):
    scenario_file = tmp_path / "scenario.json"
    scenario_file.write_text(
        '{"title": "Incomplete scenario"}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing required fields"):
        load_scenario(scenario_file)
