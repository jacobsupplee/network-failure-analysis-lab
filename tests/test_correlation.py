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

def test_apipa_evidence_prioritizes_dhcp_configuration():
    results = [
        {
            "diagnostic_type": "dhcp",
            "analysis": {
                "status": "no_apipa",
                "finding": "IP address is outside the APIPA range.",
                "evidence": [
                    {"observation": "IPv4 address", "result": "169.254.12.34"},
                ],
            },
        }
    ]

    report = correlate_findings(results)

    assert report["status"] == "investigate"
    assert report["likely_causes"][0]["cause"] == (
        "DHCP or IP configuration problem"
    )

def test_unreachable_gateway_prioritizes_local_connectivity():
    results = [
        {
            "diagnostic_type": "connectivity",
            "analysis": {
                "status": "connected",
                "finding": "Gateway reachability test failed.",
                "evidence": [
                    {"item": "Gateway reachability", "value": "Unreachable"},
                    {"item": "External reachability", "value": "Reachable"},
                ],
            },
        }
    ]

    report = correlate_findings(results)

    assert report["status"] == "investigate"
    assert report["likely_causes"][0]["cause"] == (
        "Local network or default gateway reachability problem"
    )

def test_unreachable_external_target_prioritizes_external_connectivity():
    results = [
        {
            "diagnostic_type": "connectivity",
            "analysis": {
                "status": "investigate",
                "finding": "Gateway responded but external target did not.",
                "evidence": [
                    {"item": "Gateway reachability", "value": "Reachable"},
                    {"item": "External reachability", "value": "Unreachable"},
                ],
            },
        }
    ]

    report = correlate_findings(results)

    assert report["status"] == "investigate"
    assert report["likely_causes"][0]["cause"] == (
        "External network reachability problem"
    )

def test_dns_failure_with_successful_connectivity_prioritizes_dns():
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
                    {"item": "Gateway reachability", "value": "Reachable"},
                    {"item": "External reachability", "value": "Reachable"},
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

def test_successful_diagnostics_report_no_failure_detected():
    results = [
        {
            "diagnostic_type": "dhcp",
            "analysis": {
                "status": "no_apipa",
                "finding": "IP address is outside the APIPA range.",
                "evidence": [
                    {"observation": "IPv4 address", "result": "10.0.0.179"},
                ],
            },
        },
        {
            "diagnostic_type": "dns",
            "analysis": {
                "status": "resolved",
                "finding": "Hostname resolved successfully.",
                "evidence": [
                    {"observation": "Resolution result", "result": "success"},
                ],
            },
        },
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
    ]

    report = correlate_findings(results)

    assert report["status"] == "no_failure_detected"
    assert report["likely_causes"] == []

def test_missing_default_route_is_correlated():
    results = [
        {
            "diagnostic_type": "routing",
            "analysis": {
                "status": "investigate",
                "finding": "No IPv4 default route was found.",
                "evidence": [
                    {
                        "observation": "Default route count",
                        "result": 0,
                    }
                ],
            },
        }
    ]

    report = correlate_findings(results)

    assert report["status"] == "investigate"
    assert any(
        cause["cause"] == "Missing IPv4 default route"
        for cause in report["likely_causes"]
    )

def test_routing_without_default_route_count_does_not_assume_missing_route():
    results = [
        {
            "diagnostic_type": "routing",
            "analysis": {
                "status": "investigate",
                "finding": "Routing requires investigation.",
                "evidence": [],
            },
        }
    ]

    report = correlate_findings(results)

    assert report["status"] == "inconclusive"
    assert not any(
        cause["cause"] == "Missing IPv4 default route"
        for cause in report["likely_causes"]
    )

def test_missing_default_route_is_correlated_with_other_findings():
    results = [
        {
            "diagnostic_type": "routing",
            "analysis": {
                "status": "investigate",
                "finding": "No IPv4 default route was found.",
                "evidence": [
                    {
                        "observation": "Default route count",
                        "result": 0,
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
                    {
                        "item": "Gateway reachable",
                        "value": True,
                    },
                    {
                        "item": "External target reachable",
                        "value": False,
                    },
                ],
            },
        },
    ]

    report = correlate_findings(results)

    assert report["status"] == "investigate"
    assert any(
        cause["cause"] == "Missing IPv4 default route"
        for cause in report["likely_causes"]
    )
    assert len(report["supporting_findings"]) == 2


def test_likely_cause_includes_traceable_supporting_evidence():
    results = [
        {
            "diagnostic_type": "routing",
            "analysis": {
                "status": "investigate",
                "finding": "No IPv4 default route was found.",
                "evidence": [
                    {
                        "observation": "Default route count",
                        "result": 0,
                    }
                ],
            },
        }
    ]

    report = correlate_findings(results)

    route_cause = next(
        cause
        for cause in report["likely_causes"]
        if cause["cause"] == "Missing IPv4 default route"
    )

    assert route_cause["supporting_evidence"]
    assert route_cause["supporting_evidence"][0] == (
        "The routing diagnostic reported zero default routes."
    )
    assert route_cause["evidence_references"]
    assert route_cause["evidence_references"][0] == {
        "report_index": 0,
        "diagnostic_type": "routing",
        "finding": "No IPv4 default route was found.",
        "observation": "Default route count",
        "value": 0,
    }
