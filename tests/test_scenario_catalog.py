from pathlib import Path

import pytest

from src.analysis_runner import run_analysis


SCENARIO_DIRECTORY = Path(__file__).resolve().parents[1] / "scenarios"
SCENARIO_FILES = sorted(SCENARIO_DIRECTORY.glob("*.json"))


@pytest.mark.parametrize(
    "scenario_path",
    SCENARIO_FILES,
    ids=lambda path: path.stem,
)
def test_bundled_scenario_matches_expected_status(scenario_path):
    result = run_analysis(scenario_path)

    assert result["matches_expected"] is True, (
        f"{scenario_path.name} expected {result['expected_status']!r}, "
        f"but analyzer returned {result['analysis']['status']!r}"
    )


def test_bundled_scenario_catalog_has_unique_ids():
    scenario_ids = [
        run_analysis(scenario_path)["scenario_id"]
        for scenario_path in SCENARIO_FILES
    ]

    assert SCENARIO_FILES, "No bundled scenario files were found"
    assert len(scenario_ids) == len(set(scenario_ids)), (
        "Bundled scenarios must use unique scenario IDs"
    )
