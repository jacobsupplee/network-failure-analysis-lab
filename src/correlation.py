import ipaddress

def correlate_findings(results: list[dict]) -> dict:
    """Combine diagnostic reports into an evidence-based assessment."""
    reports = [
        {
            "diagnostic_type": result.get("diagnostic_type", "unknown"),
            "status": result["analysis"]["status"],
            "finding": result["analysis"]["finding"],
            "evidence": result["analysis"].get("evidence", []),
        }
        for result in results
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

    reports_by_type = {
        report["diagnostic_type"]: report
        for report in reports
    }
    statuses = {
        report["diagnostic_type"]: report["status"]
        for report in reports
    }
    supporting_findings = [
        {
            "diagnostic_type": report["diagnostic_type"],
            "status": report["status"],
            "finding": report["finding"],
        }
        for report in reports
    ]

    def normalize_evidence(evidence) -> dict:
        if isinstance(evidence, dict):
            return evidence
        normalized = {}
        if isinstance(evidence, list):
            for item in evidence:
                if not isinstance(item, dict):
                    continue
                label = item.get(
                    "observation",
                    item.get("item", item.get("check", "")),
                )
                value = item.get("result", item.get("value"))
                if label:
                    normalized[label] = value
        return normalized

    def get_evidence(diagnostic_type: str) -> dict:
        report = reports_by_type.get(diagnostic_type, {})
        return normalize_evidence(report.get("evidence", []))

    def is_reachable(value) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"reachable", "true", "yes", "success"}:
                return True
            if normalized in {"unreachable", "false", "no", "failed", "timeout"}:
                return False
        return None

    conflicts = []
    gateway_observations = []

    for report in reports:
        if report["diagnostic_type"] != "connectivity":
            continue
        evidence = report["evidence"]
        if isinstance(evidence, dict):
            items = [
                {"observation": key, "result": value}
                for key, value in evidence.items()
            ]
        elif isinstance(evidence, list):
            items = evidence
        else:
            continue

        for item in items:
            if not isinstance(item, dict):
                continue
            label = str(
                item.get(
                    "observation",
                    item.get("item", item.get("check", "")),
                )
            ).strip().lower()
            if label not in {
                "gateway reachability",
                "gateway reachable",
                "gateway_reachable",
            }:
                continue
            value = is_reachable(item.get("result", item.get("value")))
            if value is not None:
                gateway_observations.append(value)

    gateway_conflict = (
        True in gateway_observations
        and False in gateway_observations
    )

    if gateway_conflict:
        conflicts.append(
            {
                "type": "contradictory_evidence",
                "description": (
                    "Gateway reachability results conflict: some observations "
                    "report the gateway as reachable while others report it "
                    "as unreachable. Repeat the test and compare the timestamps "
                    "and network conditions."
                ),
            }
        )

    dhcp_evidence = get_evidence("dhcp")
    dns_evidence = get_evidence("dns")
    connectivity_evidence = get_evidence("connectivity")
    routing_evidence = get_evidence("routing")
    ports_reports = [
        report for report in reports
        if report["diagnostic_type"] == "ports"
    ]

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

    dns_result = dns_evidence.get("Resolution result")
    if dns_result is None:
        dns_result = dns_evidence.get("resolution_result")
    if isinstance(dns_result, str):
        dns_result = dns_result.strip().lower()

    default_route_count = routing_evidence.get("Default route count")
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
        dns_result in {"failed", "timeout", "nxdomain"}
        or statuses.get("dns") == "investigate"
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
            else:
                score = min(50 + evidence_count * 5, 70)
                explanation = (
                    "The diagnostic evidence warrants investigation, but the "
                    "available observations do not establish a specific cause."
                )

            if gateway_conflict:
                cause["confidence"] = "Low"
                score = min(score, 50)
                explanation += (
                    " Gateway observations conflict, so this assessment should "
                    "be treated cautiously until reachability is retested."
                )

            cause["priority_score"] = score
            cause["priority_explanation"] = explanation

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

    if any(
        status in {"inconclusive", "investigate"}
        for status in statuses.values()
    ):
        return {
            "status": "inconclusive",
            "finding": (
                "The available evidence does not establish a specific root "
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
