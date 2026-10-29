from src.correlation import correlate_findings


def make_report(diagnostic_type, status, finding, evidence):
    return {
        "diagnostic_type": diagnostic_type,
        "analysis": {
            "status": status,
            "finding": finding,
            "evidence": evidence,
        },
    }


def test_dns_failure_and_successful_tcp_by_ip_keep_the_findings_separate():
    """A working IP-based TCP test does not establish that DNS works."""
    results = [
        make_report(
            "dns",
            "investigate",
            "DNS resolution for the requested hostname timed out.",
            [{"observation": "Resolution result", "result": "timeout"}],
        ),
        make_report(
            "ports",
            "reachable",
            "TCP connection to 203.0.113.10:443 succeeded.",
            [
                {"observation": "Target host", "result": "203.0.113.10"},
                {"observation": "Target port", "result": 443},
                {"observation": "TCP connection result", "result": "connected"},
            ],
        ),
    ]

    report = correlate_findings(results)

    causes = {cause["cause"] for cause in report["likely_causes"]}

    assert report["status"] == "investigate"
    assert "DNS resolution problem" in causes
    assert "TCP port-specific connectivity problem" not in causes
    assert len(report["supporting_findings"]) == 2


def test_missing_default_route_and_external_failure_prioritize_routing():
    """Multiple symptoms should lead to a routing-focused next step."""
    results = [
        make_report(
            "routing",
            "investigate",
            "No IPv4 default route was found.",
            [{"observation": "Default route count", "result": 0}],
        ),
        make_report(
            "connectivity",
            "investigate",
            "The gateway responded but the external target did not.",
            [
                {"observation": "Gateway reachability", "result": "reachable"},
                {"observation": "External reachability", "result": "unreachable"},
            ],
        ),
        make_report(
            "ports",
            "inconclusive",
            "TCP connection to example.com:443 timed out.",
            [
                {"observation": "Target host", "result": "example.com"},
                {"observation": "Target port", "result": 443},
                {"observation": "TCP connection result", "result": "timeout"},
            ],
        ),
    ]

    report = correlate_findings(results)

    causes = {
        cause["cause"]: cause for cause in report["likely_causes"]
    }

    assert report["status"] == "investigate"
    assert "Missing IPv4 default route" in causes
    assert causes["Missing IPv4 default route"]["confidence"] == "High"
    assert "default route" in report["next_step"].lower()
    assert len(report["supporting_findings"]) == 3
