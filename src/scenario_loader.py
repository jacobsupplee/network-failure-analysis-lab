import json
from pathlib import Path

def load_scenario(path: str | Path) -> dict:
    """Load a network failure scenario from a JSON file."""

    scenario_path = Path(path)

    with scenario_path.open("r", encoding="utf-8") as file:
        scenario = json.load(file)

    required_fields = {
        "scenario_id",
        "title",
        "evidence",
        "expected_status",
    }

    missing_fields = required_fields - scenario.keys()

    if missing_fields:
        missing = ", ".join(sorted(missing_fields))
        raise ValueError(f"Scenario is missing required fields: {missing}")

    if not isinstance(scenario["evidence"], dict):
        raise ValueError("Scenario evidence must be a JSON object.")

    return scenario
