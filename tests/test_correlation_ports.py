from src.correlation import correlate_findings

def test_refused_tcp_connection_identifies_service_level_problem():
    results = [
        {
            "diagnostic_type": "connectivity",
            "analysis": {
                "status": "connected",
                "finding": "Gateway and external target responded.",
                "evidence": [
                    {"item": "Gateway reachability", "value": "Reachable"},
                    {"item": "External reachability", "value": "Reachable"},
                ],
            },
        },
        {
            "diagnostic_type": "ports",
            "analysis": {
                "status": "investigate",
                "finding": "The TCP connection to example.com:443 was refused.",
                "evidence": [
                    {"observation": "Target host", "result": "example.com"},
                    {"observation": "Target port", "result": 443},
                    {"observation": "TCP connection result", "result": "refused"},
                ],
            },
        },
    ]

    report = correlate_findings(results)

    assert report["status"] == "investigate"
    assert any(
        cause["cause"] == "TCP service unavailable or connection actively rejected"
        for cause in report["likely_causes"]
    )

def test_tcp_timeout_remains_uncertain_when_general_connectivity_works():
    results = [
        {
            "diagnostic_type": "connectivity",
            "analysis": {
                "status": "connected",
                "finding": "Gateway and external target responded.",
                "evidence": [
                    {"item": "Gateway reachability", "value": "Reachable"},
                    {"item": "External reachability", "value": "Reachable"},
                ],
            },
        },
        {
            "diagnostic_type": "ports",
            "analysis": {
                "status": "inconclusive",
                "finding": "The TCP connection to example.com:443 timed out.",
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
    assert any(
        cause["cause"] == "TCP port-specific connectivity problem"
        for cause in report["likely_causes"]
    )
    assert any(
        "filtering" in cause["reason"].lower()
        for cause in report["likely_causes"]
        if cause["cause"] == "TCP port-specific connectivity problem"
    )

def test_successful_tcp_connection_does_not_create_a_port_failure():
    results = [
        {
            "diagnostic_type": "ports",
            "analysis": {
                "status": "reachable",
                "finding": "TCP connection to example.com:443 succeeded.",
                "evidence": [
                    {"observation": "Target host", "result": "example.com"},
                    {"observation": "Target port", "result": 443},
                    {"observation": "TCP connection result", "result": "connected"},
                ],
            },
        }
    ]

    report = correlate_findings(results)

    assert report["status"] == "no_failure_detected"
    assert not any(
        cause["cause"] in {
            "TCP service unavailable or connection actively rejected",
            "TCP port-specific connectivity problem",
        }
        for cause in report["likely_causes"]
    )

def test_multiple_tcp_reports_preserve_failures_on_different_ports():
    results = [
        {
            "diagnostic_type": "ports",
            "analysis": {
                "status": "investigate",
                "finding": "TCP connection to example.com:443 was refused.",
                "evidence": [
                    {"observation": "Target host", "result": "example.com"},
                    {"observation": "Target port", "result": 443},
                    {"observation": "TCP connection result", "result": "refused"},
                ],
            },
        },
        {
            "diagnostic_type": "ports",
            "analysis": {
                "status": "inconclusive",
                "finding": "TCP connection to example.com:8443 timed out.",
                "evidence": [
                    {"observation": "Target host", "result": "example.com"},
                    {"observation": "Target port", "result": 8443},
                    {"observation": "TCP connection result", "result": "timeout"},
                ],
            },
        },
    ]

    report = correlate_findings(results)

    causes = {cause["cause"] for cause in report["likely_causes"]}

    assert report["status"] == "investigate"
    assert "TCP service unavailable or connection actively rejected" in causes
    assert "TCP port-specific connectivity problem" in causes
    assert len(report["supporting_findings"]) == 2
