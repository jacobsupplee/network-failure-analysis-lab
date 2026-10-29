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
    for name in ("subheader", "success", "warning", "info", "write",
                 "json", "markdown", "caption", "dataframe"):
        monkeypatch.setattr(
            st, name, lambda *args, _name=name, **kwargs: calls.append((_name, args))
        )
    monkeypatch.setattr(st, "columns", lambda count: [FakeColumn(calls) for _ in range(count)])
    monkeypatch.setattr(st, "expander", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(st, "container", lambda *args, **kwargs: nullcontext())
    return calls


def test_display_correlation_renders_ranked_causes_and_evidence(monkeypatch):
    calls = install_streamlit_mocks(monkeypatch)
    correlation = {
        "status": "investigate",
        "finding": "Likely outbound filtering",
        "likely_causes": [
            {
                "cause": "Outbound firewall rule",
                "reason": "A matching block rule may affect the target.",
                "confidence": "medium",
                "priority_score": 72,
                "priority_explanation": "Multiple checks support this lead.",
                "supporting_evidence": ["TCP connection failed", "Matching rule found"],
                "evidence_references": [{"diagnostic": "LIVE-PORTS"}],
            },
            {
                "cause": "Routing issue",
                "reason": "Route needs review.",
                "confidence": "low",
                "priority_score": None,
            },
        ],
        "next_step": "Inspect the matching rule and retest.",
        "supporting_findings": [{"check": "TCP", "status": "failed"}],
        "conflicts": [{"field": "connectivity", "observations": ["reachable", "unreachable"]}],
    }

    application.display_correlation(correlation)

    assert ("subheader", ("Overall Root-Cause Assessment",)) in calls
    assert ("warning", ("Investigation required: Likely outbound filtering",)) in calls
    assert ("markdown", ("#### Likely failure areas",)) in calls
    assert ("markdown", ("**1. Outbound firewall rule**",)) in calls
    assert ("metric", ("Troubleshooting priority", "72/100")) in calls
    assert ("caption", ("Priority score helps order investigation; it is not a probability that this cause is correct.",)) in calls
    assert ("json", ([{"diagnostic": "LIVE-PORTS"}],)) in calls
    assert ("write", ("Not scored",)) in calls
    assert ("write", ("Inspect the matching rule and retest.",)) in calls
    assert ("dataframe", ([{"check": "TCP", "status": "failed"}],)) in calls
    assert ("warning", ("Some observations conflict. Repeat the affected tests before relying on the assessment.",)) in calls
    assert ("json", ([{"field": "connectivity", "observations": ["reachable", "unreachable"]}],)) in calls


def test_display_correlation_handles_missing_causes_and_findings(monkeypatch):
    calls = install_streamlit_mocks(monkeypatch)

    application.display_correlation({"status": "inconclusive"})

    assert ("info", ("Inconclusive: No overall finding was provided.",)) in calls
    assert ("info", ("No likely causes were identified from the available results.",)) in calls
    assert ("write", ("Run additional diagnostics to gather more evidence.",)) in calls
    assert ("write", ("No supporting findings were recorded.",)) in calls
    assert not any("Some observations conflict" in str(args) for _, args in calls)
