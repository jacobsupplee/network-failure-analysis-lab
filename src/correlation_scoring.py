"""Troubleshooting-priority ranking and scoring for correlated causes."""


def rank_and_score_causes(
    likely_causes: list[dict],
    external_reachable,
    tcp_timeout_detected: bool,
    missing_default_route: bool,
    apipa_detected: bool,
    conflicts: list[dict],
    dns_conflict: bool,
) -> None:
    priority_order = {
        "Missing IPv4 default route": 1,
        "DHCP or IP configuration problem": 2,
        "Local network or default gateway reachability problem": 3,
        "External network reachability problem": 4,
        "Network connectivity problem": 4,
        "DNS resolution problem": 5,
        "TCP target or network path unavailable": 6,
        "TCP service unavailable or connection actively rejected": 7,
        "TCP port-specific connectivity problem": 8,
    }
    likely_causes.sort(
        key=lambda cause: priority_order.get(cause["cause"], 99)
    )

    for rank, cause in enumerate(likely_causes, start=1):
        cause["priority_rank"] = rank
        cause_name = cause["cause"]
        evidence_count = len(cause["supporting_evidence"])

        if cause_name == "Missing IPv4 default route":
            if external_reachable is False and tcp_timeout_detected:
                score = 95
                explanation = (
                    "A missing default route was directly observed, "
                    "and external connectivity failure plus a TCP timeout "
                    "corroborate its troubleshooting priority. This does "
                    "not prove it is the only cause."
                )
            elif external_reachable is False:
                score = 85
                explanation = (
                    "A missing default route was directly observed and "
                    "external connectivity failed, supporting high "
                    "troubleshooting priority."
                )
            else:
                score = 70
                explanation = (
                    "A missing default route was directly observed. "
                    "Further connectivity evidence is needed to establish "
                    "its impact."
                )
        elif cause_name == "External network reachability problem":
            if tcp_timeout_detected:
                score = 80
                explanation = (
                    "The gateway responded, external connectivity failed, "
                    "and a TCP timeout provides corroborating evidence."
                )
            else:
                score = 65
                explanation = (
                    "The gateway responded but the external reachability "
                    "test failed. Additional tests are needed to isolate "
                    "the cause."
                )
        elif cause_name == "TCP port-specific connectivity problem":
            if external_reachable is False or missing_default_route:
                score = 60
                explanation = (
                    "The TCP timeout is accompanied by broader network "
                    "failure evidence, increasing its troubleshooting priority "
                    "without isolating the cause."
                )
            else:
                score = 35
                explanation = (
                    "The TCP timeout is isolated. It warrants investigation, "
                    "but does not distinguish filtering, service availability, "
                    "or a network-path problem."
                )
        elif cause_name == "TCP service unavailable or connection actively rejected":
            score = 55
            explanation = (
                "The target actively refused the TCP connection. Check "
                "whether the service is listening or a device rejected "
                "the connection; the result does not identify which."
            )
        elif cause_name == "TCP target or network path unavailable":
            score = 65
            explanation = (
                "The TCP test reported an unreachable target, so addressing "
                "and routing merit investigation before service-level causes."
            )
        elif cause_name == "DHCP or IP configuration problem":
            score = 85 if apipa_detected else 65
            explanation = (
                "The IP configuration diagnostic requires investigation"
                + (
                    " and the reported address is in the APIPA range."
                    if apipa_detected
                    else "."
                )
            )
        elif cause_name == "Local network or default gateway reachability problem":
            score = 75
            explanation = (
                "The gateway reachability test failed. Local connectivity "
                "and possible ICMP filtering should be checked."
            )
        elif cause_name == "DNS resolution problem":
            score = 65
            explanation = (
                "DNS resolution failed or timed out. Confirm the DNS server "
                "and compare results with the connectivity tests."
            )
            if dns_conflict:
                explanation += (
                    " Contradictory DNS observations reduce certainty until "
                    "the test is repeated."
                )
        else:
            score = min(50 + evidence_count * 5, 70)
            explanation = (
                "The diagnostic evidence warrants investigation, but the "
                "available observations do not establish a specific cause."
            )

        if conflicts:
            cause["confidence"] = "Low"
            score = min(score, 50)
            explanation += (
                " Conflicting diagnostic observations reduce certainty; "
                "repeat the affected tests before relying on this assessment."
            )

        cause["priority_score"] = score
        cause["priority_explanation"] = explanation
