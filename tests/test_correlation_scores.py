from src.correlation import correlate_findings

def test_correlated_routing_failure_receives_explainable_priority_score():
    results = [
        {
            "diagnostic_type": "routing",
            "analysis": {
                "status": "investigate",
                "finding": "No IPv4 default route was found.",
                "evidence": [
                    {"item": "Default route count", "value": 0},
                ],
            },
        },
        {
            "diagnostic_type": "connectivity",
            "analysis": {
                "status": "investigate",
                "finding": "Gateway responds, but external connectivity fails.",
                "evidence": [
                    {"item": "Gateway reachability", "value": "Reachable"},
                    {"item": "External reachability", "value": "Unreachable"},
                ],
            },
        },
        {
            "diagnostic_type": "ports",
            "analysis": {
                "status": "inconclusive",
                "finding": "TCP connection to example.com:443 timed out.",
                "evidence": [
                    {"observation": "Target host", "result": "example.com"},
                    {"observation": "Target port", "result": 443},
                    {"observation": "TCP connection result", "result": "timeout"},
                ],
            },
        },
    ]

    report = correlate_findings(results)

    route_cause = next(
        cause
        for cause in report["likely_causes"]
        if cause["cause"] == "Missing IPv4 default route"
    )

    assert isinstance(route_cause["priority_score"], int)
    assert 0 <= route_cause["priority_score"] <= 100
    assert route_cause["priority_explanation"]
    assert "default route" in route_cause["priority_explanation"].lower()
    assert "external" in route_cause["priority_explanation"].lower()

def test_isolated_tcp_timeout_receives_limited_priority():
    results = [
        {
            "diagnostic_type": "ports",
            "analysis": {
                "status": "inconclusive",
                "finding": "TCP connection to example.com:443 timed out.",
                "evidence": [
                    {"observation": "Target host", "result": "example.com"},
                    {"observation": "Target port", "result": 443},
                    {"observation": "TCP connection result", "result": "timeout"},
                ],
            },
        },
    ]

    report = correlate_findings(results)

    tcp_cause = next(
        cause
        for cause in report["likely_causes"]
        if cause["cause"] == "TCP port-specific connectivity problem"
    )

    assert tcp_cause["priority_score"] <= 50
    assert "timeout" in tcp_cause["priority_explanation"].lower()
    assert tcp_cause["confidence"] == "Low"

def test_priority_score_is_not_presented_as_probability():
    results = [
        {
            "diagnostic_type": "ports",
            "analysis": {
                "status": "inconclusive",
                "finding": "TCP connection to example.com:443 timed out.",
                "evidence": [
                    {"observation": "Target host", "result": "example.com"},
                    {"observation": "Target port", "result": 443},
                    {"observation": "TCP connection result", "result": "timeout"},
                ],
            },
        },
    ]

    report = correlate_findings(results)

    tcp_cause = next(
        cause
        for cause in report["likely_causes"]
        if cause["cause"] == "TCP port-specific connectivity problem"
    )

    assert "probability" not in tcp_cause["priority_explanation"].lower()
    assert "chance" not in tcp_cause["priority_explanation"].lower()