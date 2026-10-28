from src.correlation import correlate_findings

def test_likely_causes_include_priority_ranks():
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

    assert report["status"] == "investigate"
    assert all(
        "priority_rank" in cause
        for cause in report["likely_causes"]
    )
    assert sorted(
        cause["priority_rank"] for cause in report["likely_causes"]
    ) == list(range(1, len(report["likely_causes"]) + 1))

def test_missing_default_route_ranks_ahead_of_correlated_symptoms():
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

    ranks = {
        cause["cause"]: cause["priority_rank"]
        for cause in report["likely_causes"]
    }

    assert ranks["Missing IPv4 default route"] < ranks[
        "External network reachability problem"
    ]
    assert ranks["Missing IPv4 default route"] < ranks[
        "TCP port-specific connectivity problem"
    ]

def test_priority_ranking_preserves_confidence_labels():
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

    assert tcp_cause["confidence"] == "Low"
    assert isinstance(tcp_cause["priority_rank"], int)
