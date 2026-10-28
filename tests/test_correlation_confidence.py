from src.correlation import correlate_findings

def test_missing_default_route_with_tcp_timeout_has_high_confidence():
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

    assert route_cause["confidence"] == "High"

def test_correlated_connectivity_and_tcp_failures_have_moderate_confidence():
    results = [
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

    network_cause = next(
        cause
        for cause in report["likely_causes"]
        if cause["cause"] == "External network reachability problem"
    )

    assert network_cause["confidence"] == "Moderate"

def test_isolated_tcp_timeout_has_low_confidence():
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
