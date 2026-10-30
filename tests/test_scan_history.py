import json

import pytest

from src.scan_history import (
    clear_scan_history,
    compare_scans,
    load_scan_history,
    save_scan,
)


def sample_scan(status="healthy", tcp_status="connected"):
    return {
        "correlation": {
            "status": status,
            "finding": "Network assessment",
        },
        "results": [
            {
                "diagnostic_type": "dhcp",
                "title": "DHCP",
                "analysis": {
                    "status": status,
                    "finding": "DHCP assessment",
                },
            },
            {
                "diagnostic_type": "ports",
                "title": "TCP",
                "analysis": {
                    "status": tcp_status,
                    "finding": "TCP assessment",
                },
            },
        ],
    }


def test_load_scan_history_returns_empty_list_when_file_is_missing(tmp_path):
    assert load_scan_history(tmp_path / "history.json") == []


def test_save_scan_persists_full_results_and_timestamp(tmp_path):
    history_path = tmp_path / "history.json"
    scan = sample_scan()

    record = save_scan(scan, history_path)
    saved_history = load_scan_history(history_path)

    assert len(saved_history) == 1
    assert saved_history[0] == record
    assert record["overall_status"] == "healthy"
    assert record["results"] == scan["results"]
    assert record["timestamp"].endswith("+00:00")
    assert record["scan_id"]


def test_save_scan_appends_without_overwriting_previous_scans(tmp_path):
    history_path = tmp_path / "history.json"

    first = save_scan(sample_scan(), history_path)
    second = save_scan(sample_scan("investigate", "timeout"), history_path)

    history = load_scan_history(history_path)
    assert len(history) == 2
    assert history[0]["scan_id"] == first["scan_id"]
    assert history[1]["scan_id"] == second["scan_id"]


def test_save_scan_rejects_invalid_scan_data(tmp_path):
    with pytest.raises(ValueError, match="results list"):
        save_scan({}, tmp_path / "history.json")


def test_load_scan_history_rejects_invalid_json(tmp_path):
    history_path = tmp_path / "history.json"
    history_path.write_text("{invalid", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid JSON"):
        load_scan_history(history_path)


def test_compare_scans_reports_status_changes(tmp_path):
    older = save_scan(sample_scan(), tmp_path / "older.json")
    newer = save_scan(sample_scan("investigate", "timeout"), tmp_path / "newer.json")

    comparison = compare_scans(older, newer)

    assert comparison["overall_changed"] is True
    assert comparison["previous_overall_status"] == "healthy"
    assert comparison["current_overall_status"] == "investigate"
    assert [change["diagnostic_type"] for change in comparison["changes"]] == [
        "dhcp",
        "ports",
    ]
    assert comparison["changes"][1]["previous_status"] == "connected"
    assert comparison["changes"][1]["current_status"] == "timeout"


def test_compare_scans_reports_resolved_and_unchanged_results(tmp_path):
    older = save_scan(sample_scan("investigate", "timeout"), tmp_path / "older.json")
    newer = save_scan(sample_scan("healthy", "connected"), tmp_path / "newer.json")

    comparison = compare_scans(older, newer)

    assert comparison["overall_changed"] is True
    assert len(comparison["changes"]) == 2
    assert comparison["changes"][1]["previous_status"] == "timeout"
    assert comparison["changes"][1]["current_status"] == "connected"


def test_compare_scans_ignores_findings_when_status_is_unchanged():
    older = {
        "overall_status": "healthy",
        "results": [{
            "diagnostic_type": "dns",
            "analysis": {"status": "resolved", "finding": "First detail"},
        }],
    }
    newer = {
        "overall_status": "healthy",
        "results": [{
            "diagnostic_type": "dns",
            "analysis": {"status": "resolved", "finding": "Updated detail"},
        }],
    }

    comparison = compare_scans(older, newer)

    assert comparison["overall_changed"] is False
    assert comparison["changes"] == []


def test_clear_scan_history_removes_saved_records(tmp_path):
    history_path = tmp_path / "history.json"
    save_scan(sample_scan(), history_path)

    clear_scan_history(history_path)

    assert load_scan_history(history_path) == []
    assert not history_path.exists()


def test_clear_scan_history_is_safe_when_file_does_not_exist(tmp_path):
    clear_scan_history(tmp_path / "missing.json")


def test_history_file_is_valid_json(tmp_path):
    history_path = tmp_path / "history.json"
    save_scan(sample_scan(), history_path)

    with history_path.open("r", encoding="utf-8") as history_file:
        assert isinstance(json.load(history_file), list)
