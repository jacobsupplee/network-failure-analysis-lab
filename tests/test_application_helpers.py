import application


def test_status_label_uses_known_labels_and_formats_unknown_statuses():
    assert application.status_label("no_failure_detected") == "No failure detected"
    assert application.status_label("custom_status") == "Custom status"


def test_show_status_message_routes_healthy_statuses_to_success(monkeypatch):
    calls = []
    monkeypatch.setattr(application.st, "success", lambda message: calls.append(("success", message)))
    monkeypatch.setattr(application.st, "warning", lambda message: calls.append(("warning", message)))
    monkeypatch.setattr(application.st, "info", lambda message: calls.append(("info", message)))

    application.show_status_message("connected", "Target responded")
    application.show_status_message("investigate", "Review the route")
    application.show_status_message("inconclusive", "Evidence unavailable")
    application.show_status_message("unknown", "No mapped status")

    assert calls == [
        ("success", "Target responded"),
        ("warning", "Review the route"),
        ("info", "Evidence unavailable"),
        ("info", "No mapped status"),
    ]


def test_make_live_result_omits_details_when_not_provided():
    analysis = {"status": "connected", "finding": "TCP connection succeeded"}

    result = application.make_live_result(
        "LIVE-PORTS",
        "TCP Port Test",
        "ports",
        analysis,
    )

    assert result == {
        "scenario_id": "LIVE-PORTS",
        "title": "TCP Port Test",
        "diagnostic_type": "ports",
        "analysis": analysis,
    }


def test_make_live_result_includes_nonempty_details():
    result = application.make_live_result(
        "LIVE-DNS",
        "Live DNS Resolution",
        "dns",
        {"status": "resolved"},
        "example.com resolved",
    )

    assert result["details"] == "example.com resolved"


def test_make_live_result_omits_empty_details():
    result = application.make_live_result(
        "LIVE-DNS",
        "Live DNS Resolution",
        "dns",
        {"status": "resolved"},
        "",
    )

    assert "details" not in result


def test_make_inconclusive_report_preserves_finding_and_next_step():
    report = application.make_inconclusive_report(
        "DNS collection failed: timeout",
        "Check DNS collection and retry hostname resolution.",
    )

    assert report["status"] == "inconclusive"
    assert report["finding"] == "DNS collection failed: timeout"
    assert report["next_step"] == "Check DNS collection and retry hostname resolution."
