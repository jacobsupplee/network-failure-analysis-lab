import json
from pathlib import Path


def load_scenario(path: str | Path) -> dict:
    """Load and validate a network failure scenario from a JSON file."""

    scenario_path = Path(path)

    with scenario_path.open("r", encoding="utf-8") as file:
        scenario = json.load(file)

    if not isinstance(scenario, dict):
        raise ValueError("Scenario must be a JSON object.")

    required_fields = {
        "scenario_id",
        "diagnostic_type",
        "title",
        "evidence",
        "expected_status",
    }

    missing_fields = required_fields - scenario.keys()
    if missing_fields:
        missing = ", ".join(sorted(missing_fields))
        raise ValueError(f"Scenario is missing required fields: {missing}")

    for field in ("scenario_id", "diagnostic_type", "title", "expected_status"):
        value = scenario[field]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Scenario {field} must be a non-empty string.")

    if not isinstance(scenario["evidence"], dict):
        raise ValueError("Scenario evidence must be a JSON object.")

    return scenario
