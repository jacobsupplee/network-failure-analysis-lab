import ipaddress

from src.correlation_evidence import build_evidence_references, detect_conflicts, is_reachable, normalize_dns_result, normalize_evidence
from src.correlation_scoring import rank_and_score_causes

def correlate_findings(results: list[dict]) -> dict:
    """Combine diagnostic reports into an evidence-based assessment."""
    reports = [
        {
            "report_index": report_index,
            "diagnostic_type": result.get("diagnostic_type", "unknown"),
            "status": result["analysis"]["status"],
            "finding": result["analysis"]["finding"],
            "evidence": result["analysis"].get("evidence", []),
        }
        for report_index, result in enumerate(results)
        if isinstance(result.get("analysis"), dict)
        and "status" in result["analysis"]
        and "finding" in result["analysis"]
    ]

    if not reports:
        return {
            "status": "inconclusive",
            "finding": "No usable diagnostic reports were provided.",
            "likely_causes": [],
            "supporting_findings": [],
            "conflicts": [],
            "next_step": "Run one or more diagnostics and collect their results.",
        }

    reports_by_type = {}
    status_priority = {
        "healthy": 0,
        "no_failure_detected": 0,
        "inconclusive": 1,
        "investigate": 2,
    }
    statuses = {}

    for report in reports:
        diagnostic_type = report["diagnostic_type"]
        reports_by_type.setdefault(diagnostic_type, []).append(report)

        current_status = statuses.get(diagnostic_type)
        new_status = report["status"]

        if current_status is None or status_priority.get(
            new_status, 1
        ) > status_priority.get(current_status, 1):
            statuses[diagnostic_type] = new_status

    supporting_findings = [
        {
            "diagnostic_type": report["diagnostic_type"],
            "status": report["status"],
            "finding": report["finding"],
        }
        for report in reports
    ]

    def get_evidence(diagnostic_type: str) -> dict:
        combined = {}
        for report in reports_by_type.get(diagnostic_type, []):
            evidence = normalize_evidence(report.get("evidence", []))
            for label, value in evidence.items():
                if label not in combined or combined[label] is None:
                    combined[label] = value
        return combined

    (
        conflicts,
        gateway_conflict,
        dns_conflict,
        external_conflict,
        routing_conflict,
        dns_observations,
    ) = detect_conflicts(reports)

    dhcp_evidence = get_evidence("dhcp")
    dns_evidence = get_evidence("dns")
    connectivity_evidence = get_evidence("connectivity")
    routing_evidence = get_evidence("routing")
    ports_reports = reports_by_type.get("ports", [])

    ip_address = dhcp_evidence.get("IPv4 address")
    if ip_address is None:
        ip_address = dhcp_evidence.get("IP address")
    if ip_address is None:
        ip_address = dhcp_evidence.get("ip_address")

    gateway_reachable = connectivity_evidence.get("Gateway reachability")
    if gateway_reachable is None:
        gateway_reachable = connectivity_evidence.get("Gateway reachable")
    if gateway_reachable is None:
        gateway_reachable = connectivity_evidence.get("gateway_reachable")
    gateway_reachable = is_reachable(gateway_reachable)

    if gateway_conflict:
        gateway_reachable = None

    external_reachable = connectivity_evidence.get("External reachability")
    if external_reachable is None:
        external_reachable = connectivity_evidence.get("External target reachable")
    if external_reachable is None:
        external_reachable = connectivity_evidence.get("external_reachable")
    external_reachable = is_reachable(external_reachable)

    if external_conflict:
        external_reachable = None

    dns_result = dns_evidence.get("Resolution result")
    if dns_result is None:
        dns_result = dns_evidence.get("resolution_result")
    if isinstance(dns_result, str):
        dns_result = dns_result.strip().lower()

    if dns_conflict:
        dns_result = next(
            value for value in dns_observations if value != "success"
        )

    default_route_count = routing_evidence.get("Default route count")
    if routing_conflict:
        default_route_count = None

    missing_default_route = (
        isinstance(default_route_count, int)
        and not isinstance(default_route_count, bool)
        and default_route_count == 0
    )

    tcp_observations = []

    for report in ports_reports:
        evidence = normalize_evidence(report["evidence"])
        result = evidence.get("TCP connection result")
        if isinstance(result, str):
            result = result.strip().lower()
        tcp_observations.append(
            {
                "host": evidence.get("Target host", "the target"),
                "port": evidence.get("Target port", "the specified port"),
                "result": result,
            }
        )

    tcp_results = {
        observation["result"]
        for observation in tcp_observations
    }
    tcp_failure_detected = bool(
        tcp_results.intersection({"refused", "timeout", "unreachable"})
    )
    tcp_timeout_detected = "timeout" in tcp_results

    apipa_detected = False
    if isinstance(ip_address, str):
        try:
            address = ipaddress.ip_address(ip_address)
            apipa_detected = (
                isinstance(address, ipaddress.IPv4Address)
                and address in ipaddress.ip_network("169.254.0.0/16")
            )
        except ValueError:
            pass

    likely_causes = []

    if statuses.get("dhcp") == "investigate" or apipa_detected:
        if apipa_detected:
            reason = (
                f"The reported IP address is {ip_address}, within the IPv4 "
                "APIPA range. This can occur when automatic address assignment "
                "fails, but the address alone does not establish the cause."
            )
        else:
            reason = (
                "The DHCP diagnostic identified a condition requiring "
                "investigation. Review the reported address and DHCP evidence."
            )

        likely_causes.append(
            {
                "cause": "DHCP or IP configuration problem",
                "reason": reason,
                "confidence": "Possible",
                "supporting_evidence": [
                    f"Reported IP address: {ip_address}"
                    if ip_address is not None
                    else "The DHCP diagnostic reported a condition requiring investigation."
                ],
            }
        )

    if missing_default_route:
        corroborating_evidence = (
            external_reachable is False
            and tcp_timeout_detected
        )
        route_confidence = "High" if corroborating_evidence else "Possible"
        route_supporting_evidence = [
            "The routing diagnostic reported zero default routes."
        ]

        if external_reachable is False:
            route_supporting_evidence.append(
                "The external connectivity test failed."
            )
        if tcp_timeout_detected:
            route_supporting_evidence.append(
                "At least one TCP connection attempt timed out."
            )

        likely_causes.append(
            {
                "cause": "Missing IPv4 default route",
                "reason": (
                    "The routing diagnostic found no IPv4 default route. "
                    "This can prevent traffic to destinations outside directly "
                    "connected networks. The failed external tests are "
                    "consistent with this finding, although they do not prove "
                    "that it is the sole cause."
                ),
                "confidence": route_confidence,
                "supporting_evidence": route_supporting_evidence,
            }
        )

    if gateway_reachable is False:
        likely_causes.append(
            {
                "cause": "Local network or default gateway reachability problem",
                "reason": (
                    "The gateway reachability test failed. Check the local "
                    "network, gateway configuration, and whether ICMP traffic "
                    "is filtered."
                ),
                "confidence": "Possible",
                "supporting_evidence": [
                    "The default gateway did not respond to the reachability test."
                ],
            }
        )
    elif gateway_reachable is True and external_reachable is False:
        external_supporting_evidence = [
            "The default gateway responded to the reachability test.",
            "The external target did not respond to the reachability test.",
        ]

        if tcp_timeout_detected:
            external_supporting_evidence.append(
                "At least one TCP connection attempt also timed out."
            )
        if missing_default_route:
            external_supporting_evidence.append(
                "The routing diagnostic reported no IPv4 default route."
            )
        elif default_route_count is not None and default_route_count > 0:
            external_supporting_evidence.append(
                "The presence of a default route does not confirm that the route is usable."
            )

        likely_causes.append(
            {
                "cause": "External network reachability problem",
                "reason": (
                    "The gateway responded, but external reachability failed. "
                    "The TCP timeout provides additional evidence of an "
                    "external connectivity concern. Routing, filtering, or "
                    "target availability may be involved."
                ),
                "confidence": (
                    "Moderate" if tcp_timeout_detected else "Possible"
                ),
                "supporting_evidence": external_supporting_evidence,
            }
        )
    elif statuses.get("connectivity") == "investigate":
        likely_causes.append(
            {
                "cause": "Network connectivity problem",
                "reason": (
                    "The connectivity analyzer identified a concern, but "
                    "the supplied evidence does not isolate the failing path."
                ),
                "confidence": "Possible",
                "supporting_evidence": [
                    "The connectivity diagnostic reported a condition requiring investigation."
                ],
            }
        )

    dns_failed = (
        dns_result in {"failed", "failure", "timeout", "nxdomain", "error"}
        or statuses.get("dns") == "investigate"
        or dns_conflict
    )

    if dns_failed:
        if gateway_reachable is True and external_reachable is True:
            reason = (
                "DNS resolution failed while gateway and external "
                "reachability tests succeeded. Prioritize DNS investigation, "
                "but verify the configured DNS server separately."
            )
        elif apipa_detected or statuses.get("dhcp") == "investigate":
            reason = (
                "DNS resolution failed alongside a DHCP or IP configuration "
                "concern. Verify network configuration and DNS settings."
            )
        elif dns_conflict:
            reason = (
                "DNS reports contain contradictory results. At least one "
                "observation indicates failure, but the available evidence "
                "does not establish whether DNS is consistently failing."
            )
        else:
            reason = (
                "DNS resolution failed or timed out. Check the hostname, "
                "configured DNS server, and DNS query response."
            )

        dns_supporting_evidence = [
            f"DNS resolution result: {dns_result}"
            if dns_result is not None
            else "The DNS diagnostic reported a condition requiring investigation."
        ]

        if dns_conflict:
            dns_supporting_evidence.append(
                "Repeated DNS reports contain contradictory resolution results."
            )
        if gateway_reachable is True:
            dns_supporting_evidence.append(
                "The default gateway responded to the reachability test."
            )
        elif gateway_reachable is False:
            dns_supporting_evidence.append(
                "The default gateway did not respond to the reachability test."
            )
        if external_reachable is True:
            dns_supporting_evidence.append(
                "The external target responded to the reachability test."
            )
        elif external_reachable is False:
            dns_supporting_evidence.append(
                "The external target did not respond to the reachability test."
            )

        likely_causes.append(
            {
                "cause": "DNS resolution problem",
                "reason": reason,
                "confidence": "Possible",
                "supporting_evidence": dns_supporting_evidence,
            }
        )

    for observation in tcp_observations:
        tcp_result = observation["result"]
        target = f'{observation["host"]}:{observation["port"]}'

        if tcp_result == "refused":
            likely_causes.append(
                {
                    "cause": "TCP service unavailable or connection actively rejected",
                    "reason": (
                        f"The TCP connection to {target} was refused. "
                        "This can indicate that no service is listening on "
                        "the port or that a network device actively rejected it."
                    ),
                    "confidence": "Possible",
                    "supporting_evidence": [
                        f"TCP connection to {target} was refused."
                    ],
                }
            )
        elif tcp_result == "timeout":
            corroborated_network_issue = (
                external_reachable is False or missing_default_route
            )
            tcp_confidence = (
                "Moderate" if corroborated_network_issue else "Low"
            )
            tcp_supporting_evidence = [
                f"The TCP connection attempt to {target} timed out.",
                "A timeout does not distinguish packet filtering from an unavailable host or service.",
            ]

            if gateway_reachable is True and external_reachable is True:
                tcp_supporting_evidence.append(
                    "Gateway and external ICMP reachability succeeded, "
                    "but that does not confirm this TCP port is accessible."
                )
            if external_reachable is False:
                tcp_supporting_evidence.append(
                    "The external connectivity test also failed."
                )
            if missing_default_route:
                tcp_supporting_evidence.append(
                    "The routing diagnostic reported no IPv4 default route."
                )

            likely_causes.append(
                {
                    "cause": "TCP port-specific connectivity problem",
                    "reason": (
                        f"The TCP connection to {target} timed out. Possible "
                        "explanations include filtering, a nonresponsive "
                        "service, or a network path issue. The timeout alone "
                        "does not identify which explanation is correct."
                    ),
                    "confidence": tcp_confidence,
                    "supporting_evidence": tcp_supporting_evidence,
                }
            )
        elif tcp_result == "unreachable":
            likely_causes.append(
                {
                    "cause": "TCP target or network path unavailable",
                    "reason": (
                        f"The TCP test for {target} reported an unreachable "
                        "target. Check addressing and routing before "
                        "concluding that the service itself is unavailable."
                    ),
                    "confidence": "Possible",
                    "supporting_evidence": [
                        f"TCP connection to {target} reported an unreachable target."
                    ],
                }
            )

    if likely_causes:
        for cause in likely_causes:
            cause["evidence_references"] = build_evidence_references(cause, reports)

        rank_and_score_causes(
            likely_causes,
            external_reachable,
            tcp_timeout_detected,
            missing_default_route,
            apipa_detected,
            conflicts,
            dns_conflict,
        )

        if conflicts:
            next_step = (
                "Repeat the conflicting diagnostic tests and compare their "
                "results under the same network conditions before selecting "
                "a root cause."
            )
        elif apipa_detected or statuses.get("dhcp") == "investigate":
            next_step = (
                "Verify IP configuration and DHCP availability first, then "
                "repeat connectivity and DNS tests."
            )
        elif missing_default_route:
            next_step = (
                "Inspect the IPv4 routing table and verify that the correct "
                "default route is configured before repeating connectivity tests."
            )
        elif gateway_reachable is False:
            next_step = (
                "Verify local network access and default gateway reachability. "
                "Check whether ICMP filtering could explain the failed test."
            )
        elif gateway_reachable is True and external_reachable is False:
            next_step = (
                "Check the route beyond the gateway, filtering rules, and "
                "external target availability."
            )
        elif tcp_failure_detected:
            next_step = (
                "Verify each affected target host and port, check whether "
                "the services are listening, and review filtering and routing evidence."
            )
        elif dns_failed:
            next_step = (
                "Inspect the DNS response and test the configured DNS server "
                "while confirming basic connectivity."
            )
        else:
            next_step = (
                "Investigate the listed failure areas using the supporting "
                "findings and targeted diagnostic tests."
            )

        return {
            "status": "investigate",
            "finding": (
                "The available evidence identifies one or more failure areas "
                "that require investigation."
            ),
            "likely_causes": likely_causes,
            "supporting_findings": supporting_findings,
            "conflicts": conflicts,
            "next_step": next_step,
        }

    if conflicts or any(
        status in {"inconclusive", "investigate"}
        for status in statuses.values()
    ):
        return {
            "status": "investigate" if conflicts else "inconclusive",
            "finding": (
                "Conflicting diagnostic evidence requires retesting before a root cause can be selected."
                if conflicts
                else "The available evidence does not establish a specific root "
                "cause, but one or more diagnostics require further investigation."
            ),
            "likely_causes": [],
            "supporting_findings": supporting_findings,
            "conflicts": conflicts,
            "next_step": (
                "Review the diagnostic findings, collect additional evidence, "
                "and repeat the relevant tests."
            ),
        }

    return {
        "status": "no_failure_detected",
        "finding": (
            "No supplied diagnostic report identified a condition requiring "
            "investigation."
        ),
        "likely_causes": [],
        "supporting_findings": supporting_findings,
        "conflicts": conflicts,
        "next_step": (
            "If the user still experiences problems, test the specific "
            "application or network service involved."
        ),
    }