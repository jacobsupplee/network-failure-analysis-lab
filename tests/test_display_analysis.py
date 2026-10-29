from contextlib import nullcontext

import application


class FakeColumn:
    def __init__(self, calls):
        self.calls = calls

    def metric(self, *args, **kwargs):
        self.calls.append(("metric", args))

    def write(self, *args, **kwargs):
        self.calls.append(("write", args))


def install_streamlit_mocks(monkeypatch):
    calls = []
    st = application.st
    for name in ("subheader", "success", "warning", "info", "write", "json",
                 "markdown", "caption", "code"):
        monkeypatch.setattr(
            st, name, lambda *args, _name=name, **kwargs: calls.append((_name, args))
        )
    monkeypatch.setattr(st, "columns", lambda count: [FakeColumn(calls) for _ in range(count)])
    monkeypatch.setattr(st, "expander", lambda *args, **kwargs: nullcontext())
    return calls


def test_display_analysis_renders_populated_live_result(monkeypatch):
    calls = install_streamlit_mocks(monkeypatch)
    result = {
        "title": "DNS diagnostic",
        "details": "query output",
        "analysis": {
            "status": "resolved",
            "finding": "Hostname resolved",
            "severity": "low",
            "next_step": "Continue testing",
            "evidence": [{"hostname": "example.com"}],
            "hypotheses": [
                {"cause": "Transient DNS issue", "reason": "Prior timeout", "confidence": "low"},
                "Unstructured hypothesis",
            ],
            "next_tests": [
                {"test": "Retry lookup", "purpose": "Check repeatability"},
                "Traceroute",
            ],
            "verification": ["Resolve hostname again"],
        },
    }

    application.display_analysis(result, live=True)

    assert ("subheader", ("DNS diagnostic",)) in calls
    assert ("success", ("Resolved: Hostname resolved",)) in calls
    assert ("json", ([{"hostname": "example.com"}],)) in calls
    assert ("markdown", ("**Transient DNS issue**",)) in calls
    assert ("write", ("Unstructured hypothesis",)) in calls
    assert ("markdown", ("**Retry lookup**",)) in calls
    assert ("write", ("Traceroute",)) in calls
    assert ("markdown", ("- Resolve hostname again",)) in calls
    assert ("code", ("query output",)) in calls
    assert not any("Scenario expectation" in str(args) for _, args in calls)


def test_display_analysis_handles_empty_optional_sections(monkeypatch):
    calls = install_streamlit_mocks(monkeypatch)

    application.display_analysis({"analysis": {"status": "inconclusive"}})

    assert ("subheader", ("Diagnostic result",)) in calls
    assert ("info", ("Inconclusive: No finding was provided.",)) in calls
    assert ("write", ("No evidence was recorded.",)) in calls
    assert ("write", ("No possible causes were identified.",)) in calls
    assert ("write", ("No additional tests were recommended.",)) in calls
    assert ("write", ("No verification steps were recorded.",)) in calls


def test_display_analysis_reports_scenario_expectation_mismatch(monkeypatch):
    calls = install_streamlit_mocks(monkeypatch)
    result = {
        "title": "DHCP diagnostic",
        "analysis": {"status": "investigate", "finding": "APIPA address detected"},
        "expected_status": "healthy",
        "matches_expected": False,
    }

    application.display_analysis(result)

    assert ("warning", ("Investigation required: APIPA address detected",)) in calls
    assert ("warning", ("Scenario result did not match the expected status.",)) in calls
