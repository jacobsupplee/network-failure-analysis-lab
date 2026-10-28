from src.correlation import correlate_findings

def test_external_failure_includes_routing_context_when_default_route_exists():
    results = [
        {
            "diagnostic_type": "routing",
            "analysis": {
                "status": "route_present",
                "finding": "An IPv4 default route was identified.",
                "evidence": [
                    {
                        "observation": "Default route count",
                        "result": 1,
                    }
                ],
            },
        },
        {
            "diagnostic_type": "connectivity",
            "analysis": {
                "status": "investigate",
                "finding": "The external target was unreachable.",
                "evidence": [
                    {"item": "Gateway reachable", "value": True},
                    {"item": "External target reachable", "value": False},
                ],
            },
        },
    ]

    report = correlate_findings(results)

    external_cause = next(
        cause
        for cause in report["likely_causes"]
        if cause["cause"] == "External network reachability problem"
    )

    assert report["status"] == "investigate"
    assert any(
        "does not confirm that the route is usable" in evidence
        for evidence in external_cause["supporting_evidence"]
    )

def test_known_cause_is_preserved_when_another_diagnostic_is_inconclusive():
    results = [
        {
            "diagnostic_type": "connectivity",
            "analysis": {
                "status": "investigate",
                "finding": "The gateway was unreachable.",
                "evidence": [
                    {"item": "Gateway reachable", "value": False},
                ],
            },
        },
        {
            "diagnostic_type": "routing",
            "analysis": {
                "status": "inconclusive",
                "finding": "The routing evidence was insufficient.",
                "evidence": [],
            },
        },
    ]

    report = correlate_findings(results)

    assert report["status"] == "investigate"
    assert any(
        cause["cause"] == "Local network or default gateway reachability problem"
        for cause in report["likely_causes"]
    )
    assert len(report["supporting_findings"]) == 2
