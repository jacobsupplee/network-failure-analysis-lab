from pathlib import Path
from src.analyzers.dhcp import analyze_dhcp
from src.analyzers.dns import analyze_dns
from src.analyzers.ports import analyze_port
from src.analyzers.routing import analyze_routing
from src.scenario_loader import load_scenario

ANALYZERS = {
    "dhcp": analyze_dhcp,
    "dns": analyze_dns,
    "ports": analyze_port,
    "routing": analyze_routing,
}

def run_analysis(path: str | Path) -> dict:
    """Load a scenario and run its designated diagnostic module."""
    scenario = load_scenario(path)
    diagnostic_type = scenario["diagnostic_type"]

    analyzer = ANALYZERS.get(diagnostic_type)

    if analyzer is None:
        raise ValueError(
            f"Unsupported diagnostic type: {diagnostic_type}"
        )

    result = analyzer(scenario["evidence"])

    return {
        "scenario_id": scenario["scenario_id"],
        "title": scenario["title"],
        "diagnostic_type": diagnostic_type,
        "analysis": result,
        "expected_status": scenario["expected_status"],
        "matches_expected": (
            result["status"] == scenario["expected_status"]
        ),
    }
