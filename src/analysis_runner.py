from pathlib import Path

from src.diagnostics import analyze_dhcp
from src.scenario_loader import load_scenario


def run_analysis(path: str | Path) -> dict:
    """Load a scenario, analyze its evidence, and compare the result."""

    scenario = load_scenario(path)
    result = analyze_dhcp(scenario["evidence"])

    return {
        "scenario_id": scenario["scenario_id"],
        "title": scenario["title"],
        "analysis": result,
        "expected_status": scenario["expected_status"],
        "matches_expected": (
            result["status"] == scenario["expected_status"]
        ),
    }
