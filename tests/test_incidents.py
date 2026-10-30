import json

import pytest

from src.incidents import (
    add_timeline_entry,
    associate_scan,
    build_incident_report_html,
    clear_incidents,
    create_incident,
    load_incidents,
    update_incident,
)


def sample_scan(scan_id="scan-001"):
    return {
        "scan_id": scan_id,
        "timestamp": "2026-10-30T12:00:00+00:00",
        "overall_status": "investigate",
        "overall_finding": "DNS resolution failed.",
        "results": [],
    }


def test_load_incidents_returns_empty_list_when_missing(tmp_path):
    assert load_incidents(tmp_path / "incidents.json") == []


def test_create_incident_saves_initial_timeline_entry(tmp_path):
    path = tmp_path / "incidents.json"

    incident = create_incident("DNS outage", "Users cannot resolve internal hosts.", "High", path)

    saved = load_incidents(path)
    assert saved == [incident]
    assert incident["status"] == "Open"
    assert incident["severity"] == "High"
    assert incident["timeline"][0]["entry_type"] == "Incident created"


def test_create_incident_requires_title_and_valid_severity(tmp_path):
    path = tmp_path / "incidents.json"

    with pytest.raises(ValueError, match="title"):
        create_incident(" ", "Description", incident_path=path)
    with pytest.raises(ValueError, match="severity"):
        create_incident("DNS outage", "Description", "Urgent", path)


def test_add_timeline_entry_appends_timestamped_note(tmp_path):
    path = tmp_path / "incidents.json"
    incident = create_incident("DNS outage", "Resolution needed.", incident_path=path)

    updated = add_timeline_entry(incident["incident_id"], "Checked DNS server reachability.", incident_path=path)

    assert len(updated["timeline"]) == 2
    assert updated["timeline"][-1]["note"] == "Checked DNS server reachability."
    assert updated["timeline"][-1]["timestamp"].endswith("+00:00")


def test_add_timeline_entry_rejects_empty_note(tmp_path):
    path = tmp_path / "incidents.json"
    incident = create_incident("DNS outage", "Description", incident_path=path)

    with pytest.raises(ValueError, match="cannot be empty"):
        add_timeline_entry(incident["incident_id"], "  ", incident_path=path)


def test_associate_scan_preserves_scan_evidence(tmp_path):
    path = tmp_path / "incidents.json"
    incident = create_incident("DNS outage", "Description", incident_path=path)

    updated = associate_scan(incident["incident_id"], sample_scan(), path)

    assert updated["associated_scans"][0]["scan_id"] == "scan-001"
    assert updated["timeline"][-1]["entry_type"] == "Evidence attached"


def test_associate_scan_rejects_duplicate_scan(tmp_path):
    path = tmp_path / "incidents.json"
    incident = create_incident("DNS outage", "Description", incident_path=path)
    associate_scan(incident["incident_id"], sample_scan(), path)

    with pytest.raises(ValueError, match="already associated"):
        associate_scan(incident["incident_id"], sample_scan(), path)


def test_resolving_incident_requires_resolution_summary(tmp_path):
    path = tmp_path / "incidents.json"
    incident = create_incident("DNS outage", "Description", incident_path=path)

    with pytest.raises(ValueError, match="resolution summary"):
        update_incident(incident["incident_id"], "Resolved", incident_path=path)


def test_update_incident_records_resolution(tmp_path):
    path = tmp_path / "incidents.json"
    incident = create_incident("DNS outage", "Description", incident_path=path)

    updated = update_incident(
        incident["incident_id"],
        "Resolved",
        "Corrected the DNS server address and confirmed name resolution.",
        path,
    )

    assert updated["status"] == "Resolved"
    assert updated["resolution"].startswith("Corrected")
    assert updated["timeline"][-1]["entry_type"] == "Status update"


def test_update_incident_rejects_unknown_status(tmp_path):
    path = tmp_path / "incidents.json"
    incident = create_incident("DNS outage", "Description", incident_path=path)

    with pytest.raises(ValueError, match="status"):
        update_incident(incident["incident_id"], "Closed", incident_path=path)


def test_report_escapes_user_supplied_html_and_includes_scan(tmp_path):
    path = tmp_path / "incidents.json"
    incident = create_incident("<script>alert(1)</script>", "Description", incident_path=path)
    incident = associate_scan(incident["incident_id"], sample_scan(), path)

    report = build_incident_report_html(incident)

    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    assert "DNS resolution failed." in report
    assert "Investigation timeline" in report


def test_clear_incidents_removes_file(tmp_path):
    path = tmp_path / "incidents.json"
    create_incident("DNS outage", "Description", incident_path=path)

    clear_incidents(path)

    assert load_incidents(path) == []
    assert not path.exists()


def test_incident_file_is_valid_json(tmp_path):
    path = tmp_path / "incidents.json"
    create_incident("DNS outage", "Description", incident_path=path)

    with path.open("r", encoding="utf-8") as incident_file:
        assert isinstance(json.load(incident_file), list)
