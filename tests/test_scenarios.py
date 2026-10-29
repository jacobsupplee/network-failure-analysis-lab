import json

import pytest

from src.scenario_loader import load_scenario


VALID_SCENARIO = {
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


def write_scenario(tmp_path, data, filename="scenario.json"):
    scenario_file = tmp_path / filename
    scenario_file.write_text(json.dumps(data), encoding="utf-8")
    return scenario_file


def test_load_valid_scenario(tmp_path):
    scenario_file = write_scenario(tmp_path, VALID_SCENARIO)

    result = load_scenario(scenario_file)

    assert result["scenario_id"] == "DHCP-001"
    assert result["evidence"]["ip_address"] == "169.254.12.34"
    assert result["diagnostic_type"] == "dhcp"


def test_reject_scenario_missing_required_fields(tmp_path):
    scenario_file = write_scenario(tmp_path, {"title": "Incomplete scenario"})

    with pytest.raises(ValueError, match="missing required fields"):
        load_scenario(scenario_file)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scenario_id", ""),
        ("scenario_id", "   "),
        ("scenario_id", None),
        ("scenario_id", 123),
        ("diagnostic_type", ""),
        ("diagnostic_type", "   "),
        ("diagnostic_type", None),
        ("diagnostic_type", 123),
        ("title", ""),
        ("title", "   "),
        ("title", None),
        ("title", 123),
        ("expected_status", ""),
        ("expected_status", "   "),
        ("expected_status", None),
        ("expected_status", 123),
    ],
)
def test_reject_empty_or_non_string_metadata(tmp_path, field, value):
    scenario = {**VALID_SCENARIO, field: value}
    scenario_file = write_scenario(tmp_path, scenario)

    with pytest.raises(ValueError, match=f"Scenario {field} must be a non-empty string"):
        load_scenario(scenario_file)


@pytest.mark.parametrize("evidence", [None, [], "not an object", 42])
def test_reject_non_object_evidence(tmp_path, evidence):
    scenario = {**VALID_SCENARIO, "evidence": evidence}
    scenario_file = write_scenario(tmp_path, scenario)

    with pytest.raises(ValueError, match="Scenario evidence must be a JSON object"):
        load_scenario(scenario_file)


@pytest.mark.parametrize("json_text", ["[1, 2, 3]", "null", '"text"', "42"])
def test_reject_non_object_json(tmp_path, json_text):
    scenario_file = tmp_path / "scenario.json"
    scenario_file.write_text(json_text, encoding="utf-8")

    with pytest.raises(ValueError, match="Scenario must be a JSON object"):
        load_scenario(scenario_file)


def test_reject_malformed_json(tmp_path):
    scenario_file = tmp_path / "malformed.json"
    scenario_file.write_text('{"scenario_id":', encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        load_scenario(scenario_file)
