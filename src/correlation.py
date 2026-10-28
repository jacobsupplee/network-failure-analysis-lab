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

    def get_evidence(diagnostic_type: str) -> dict:
        report = reports_by_type.get(diagnostic_type, {})
        evidence = report.get("evidence", [])

        if isinstance(evidence, dict):
            return evidence

        normalized = {}
        if isinstance(evidence, list):
            for item in evidence:
                if not isinstance(item, dict):
                    continue
                label = item.get("observation", item.get("item", ""))
                value = item.get("result", item.get("value"))
                if label:
                    normalized[label] = value

        return normalized

    def normalize_evidence(evidence) -> dict:
        if isinstance(evidence, dict):
            return evidence

        normalized = {}
        if isinstance(evidence, list):
            for item in evidence:
                if not isinstance(item, dict):
                    continue
                label = item.get("observation", item.get("item", ""))
                value = item.get("result", item.get("value"))
                if label:
                    normalized[label] = value

        return normalized

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

    external_reachable = connectivity_evidence.get("External reachability")
    if external_reachable is None:
        external_reachable = connectivity_evidence.get("External target reachable")
    if external_reachable is None:
        external_reachable = connectivity_evidence.get("external_reachable")

    dns_result = dns_evidence.get("Resolution result")
    if dns_result is None:
        dns_result = dns_evidence.get("resolution_result")

    if isinstance(dns_result, str):
        dns_result = dns_result.strip().lower()

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

    gateway_reachable = is_reachable(gateway_reachable)
    external_reachable = is_reachable(external_reachable)

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
    routing_status = statuses.get("routing")
    default_route_count = routing_evidence.get("Default route count")

    if routing_status == "investigate" and default_route_count == 0:
        likely_causes.append(
            {
                "cause": "Missing IPv4 default route",
                "reason": (
                    "The routing diagnostic found no IPv4 default route. "
                    "Without a suitable default route, traffic destined for "
                    "networks outside directly connected routes may not "
                    "reach its destination."
                ),
                "confidence": "Possible",
                "supporting_evidence": [
                    "The routing diagnostic reported zero default routes."
                ],
            }
        )

    if apipa_detected or statuses.get("dhcp") == "investigate":
        reason = (
            f"The reported IP address is {ip_address}, which is within the "
            "IPv4 APIPA range."
            if apipa_detected
            else "The DHCP diagnostic identified a condition requiring investigation."
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

        if routing_status == "route_present":
            external_supporting_evidence.append(
                "The routing diagnostic identified a default route, "
                "but its presence does not confirm that the route is usable."
            )

        likely_causes.append(
            {
                "cause": "External network reachability problem",
                "reason": (
                    "The gateway responded, but the external target did not. "
                    "Investigate routing, filtering, or target availability; "
                    "a failed ping alone does not prove an outage."
                ),
                "confidence": "Possible",
                "supporting_evidence": external_supporting_evidence,
            }
        )
    elif statuses.get("connectivity") == "investigate":
        likely_causes.append(
            {
                "cause": "Network connectivity problem",
                "reason": (
                    "The connectivity analyzer identified a reachability "
                    "concern, but the supplied evidence does not isolate "
                    "the failing network path."
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
                "DNS resolution failed while gateway and external reachability "
                "tests succeeded. Prioritize DNS investigation, but verify "
                "the configured DNS server separately."
            )
        elif apipa_detected or statuses.get("dhcp") == "investigate":
            reason = (
                "DNS resolution failed alongside a DHCP or IP configuration "
                "concern. Verify network configuration and DNS settings "
                "before isolating the DNS service."
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

    tcp_failure_detected = False

    for ports_report in ports_reports:
        ports_evidence = normalize_evidence(ports_report["evidence"])
        tcp_result = ports_evidence.get("TCP connection result")

        if isinstance(tcp_result, str):
            tcp_result = tcp_result.strip().lower()

        target_host = ports_evidence.get("Target host", "the target")
        target_port = ports_evidence.get("Target port", "the specified port")
        target_description = f"{target_host}:{target_port}"

        if tcp_result == "refused":
            tcp_failure_detected = True
            likely_causes.append(
                {
                    "cause": "TCP service unavailable or connection actively rejected",
                    "reason": (
                        f"The TCP connection to {target_description} was refused. "
                        "This can indicate that no service is listening on the "
                        "port or that a network device actively rejected it."
                    ),
                    "confidence": "Possible",
                    "supporting_evidence": [
                        f"TCP connection to {target_description} was refused."
                    ],
                }
            )
        elif tcp_result == "timeout":
            tcp_failure_detected = True
            tcp_supporting_evidence = [
                f"The TCP connection attempt to {target_description} timed out.",
                "A timeout does not distinguish packet filtering from an unavailable host or service.",
            ]

            if gateway_reachable is True and external_reachable is True:
                tcp_supporting_evidence.append(
                    "Gateway and external ICMP reachability tests succeeded, "
                    "but they do not confirm that this TCP port is accessible."
                )

            likely_causes.append(
                {
                    "cause": "TCP port-specific connectivity problem",
                    "reason": (
                        f"The TCP connection to {target_description} timed out. "
                        "Possible explanations include filtering, a nonresponsive "
                        "service, or a network path issue; the available evidence "
                        "does not identify which one."
                    ),
                    "confidence": "Possible",
                    "supporting_evidence": tcp_supporting_evidence,
                }
            )
        elif tcp_result == "unreachable":
            tcp_failure_detected = True
            likely_causes.append(
                {
                    "cause": "TCP target or network path unavailable",
                    "reason": (
                        f"The TCP test for {target_description} reported an "
                        "unreachable target. Check addressing and routing before "
                        "concluding that the service itself is unavailable."
                    ),
                    "confidence": "Possible",
                    "supporting_evidence": [
                        f"TCP connection to {target_description} reported an unreachable target."
                    ],
                }
            )

    if likely_causes:
        if apipa_detected or statuses.get("dhcp") == "investigate":
            next_step = (
                "Verify IP configuration and DHCP availability first, then "
                "repeat connectivity and DNS tests."
            )
        elif routing_status == "investigate" and default_route_count == 0:
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
                "Verify each affected target host and port, check whether the "
                "services are listening, and review relevant filtering and route evidence."
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
        "next_step": (
            "If the user still experiences problems, test the specific "
            "application or network service involved."
        ),
    }
