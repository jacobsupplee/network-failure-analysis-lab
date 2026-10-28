from src.correlation import correlate_findings

def make_report(diagnostic_type, finding, evidence, status="investigate"):
    return {
        "diagnostic_type": diagnostic_type,
        "analysis": {
            "status": status,
            "finding": finding,
            "evidence": evidence,
        },
    }

def make_gateway_reports():
    return [
        make_report(
            "connectivity",
            "Gateway is reachable",
            [{"check": "Gateway reachability", "result": "reachable"}],
        ),
        make_report(
            "connectivity",
            "Gateway is unreachable",
            [{"check": "Gateway reachability", "result": "unreachable"}],
        ),
    ]

def test_conflicting_gateway_results_are_preserved():
    report = correlate_findings(make_gateway_reports())

    assert report["status"] == "investigate"
    assert len(report["conflicts"]) >= 1
    assert any(
        "gateway" in conflict["description"].lower()
        for conflict in report["conflicts"]
    )

def test_conflicting_gateway_results_do_not_select_last_observation():
    report = correlate_findings(make_gateway_reports())

    causes = [
        cause["cause"]
        for cause in report["likely_causes"]
    ]

    assert "Local network or default gateway reachability problem" not in causes

def test_conflict_recommends_repeating_the_test():
    report = correlate_findings(make_gateway_reports())

    assert any(
        word in report["next_step"].lower()
        for word in ("repeat", "conflicting", "compare")
    )

def test_consistent_gateway_results_do_not_create_conflict():
    results = [
        make_report(
            "connectivity",
            "Gateway is reachable",
            [{"check": "Gateway reachability", "result": "reachable"}],
        ),
        make_report(
            "connectivity",
            "Gateway is reachable",
            [{"check": "Gateway reachability", "result": "reachable"}],
        ),
    ]

    report = correlate_findings(results)

    assert report["conflicts"] == []

def test_conflicting_gateway_results_are_not_treated_as_known_reachability():
    report = correlate_findings(make_gateway_reports())

    assert report["conflicts"]
    assert not any(
        cause["cause"] == "Local network or default gateway reachability problem"
        for cause in report["likely_causes"]
    )
    assert "conflicting" in report["next_step"].lower()
