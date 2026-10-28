from src.correlation import correlate_findings

def test_dns_failure_is_reported_as_a_possible_cause():
    results = [
        {
            "diagnostic_type": "dns",
            "analysis": {
                "status": "investigate",
                "finding": "DNS resolution timed out.",
            },
        },
        {
            "diagnostic_type": "connectivity",
            "analysis": {
                "status": "connected",
                "finding": "Gateway and external target responded.",
            },
        },
    ]

    report = correlate_findings(results)

    assert report["status"] == "investigate"
    assert report["likely_causes"][0]["cause"] == "DNS resolution problem"
    assert len(report["supporting_findings"]) == 2

def test_empty_results_are_inconclusive():
    report = correlate_findings([])

    assert report["status"] == "inconclusive"
    assert report["likely_causes"] == []

def test_inconclusive_results_do_not_claim_a_confirmed_failure():
    results = [
        {
            "diagnostic_type": "dns",
            "analysis": {
                "status": "inconclusive",
                "finding": "DNS resolution was not tested.",
            },
        }
    ]

    report = correlate_findings(results)

    assert report["status"] == "inconclusive"
    assert report["likely_causes"] == []

def test_dns_failure_with_working_connectivity_prioritizes_dns():
    results = [
        {
            "diagnostic_type": "dns",
            "analysis": {
                "status": "investigate",
                "finding": "DNS resolution timed out.",
                "evidence": [
                    {"observation": "Resolution result", "result": "timeout"},
                ],
            },
        },
        {
            "diagnostic_type": "connectivity",
            "analysis": {
                "status": "connected",
                "finding": "Gateway and external target responded.",
                "evidence": [
                    {"observation": "Gateway reachable", "result": True},
                    {"observation": "External target reachable", "result": True},
                ],
            },
        },
    ]

    report = correlate_findings(results)

    dns_cause = next(
        cause
        for cause in report["likely_causes"]
        if cause["cause"] == "DNS resolution problem"
    )

    assert report["status"] == "investigate"
    assert "Prioritize DNS investigation" in dns_cause["reason"]
    assert "DNS server" in dns_cause["reason"]

def test_dhcp_and_dns_failures_recommend_configuration_first():
    results = [
        {
            "diagnostic_type": "dhcp",
            "analysis": {
                "status": "investigate",
                "finding": "The workstation has an APIPA address.",
                "evidence": [
                    {"observation": "IP address", "result": "169.254.12.34"},
                ],
            },
        },
        {
            "diagnostic_type": "dns",
            "analysis": {
                "status": "investigate",
                "finding": "DNS resolution timed out.",
                "evidence": [
                    {"observation": "Resolution result", "result": "timeout"},
                ],
            },
        },
    ]

    report = correlate_findings(results)

    assert report["status"] == "investigate"
    assert "DHCP availability first" in report["next_step"]
    assert len(report["likely_causes"]) == 2
