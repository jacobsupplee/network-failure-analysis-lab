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

        if isinstance(evidence, list):
            return {
                item.get("observation", ""): item.get("result")
                for item in evidence
                if isinstance(item, dict)
            }

        return {}

    dhcp_evidence = get_evidence("dhcp")
    dns_evidence = get_evidence("dns")
    connectivity_evidence = get_evidence("connectivity")

    ip_address = dhcp_evidence.get("IP address")
    if ip_address in (None, "Not provided", ""):
        ip_address = dhcp_evidence.get("ip_address")

    gateway_reachable = connectivity_evidence.get("Gateway reachable")
    if gateway_reachable is None:
        gateway_reachable = connectivity_evidence.get("gateway_reachable")

    external_reachable = connectivity_evidence.get("External target reachable")
    if external_reachable is None:
        external_reachable = connectivity_evidence.get("external_reachable")

    dns_result = dns_evidence.get("Resolution result")
    if dns_result in (None, "Not tested", ""):
        dns_result = dns_evidence.get("resolution_result")

    if isinstance(dns_result, str):
        dns_result = dns_result.strip().lower()

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
            }
        )
    elif gateway_reachable is True and external_reachable is False:
        likely_causes.append(
            {
                "cause": "External network reachability problem",
                "reason": (
                    "The gateway responded, but the external target did not. "
                    "Investigate routing, filtering, or the target itself; "
                    "a failed ping alone does not prove an outage."
                ),
                "confidence": "Possible",
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
            }
        )

    if dns_result in {"failed", "timeout", "nxdomain"} or statuses.get("dns") == "investigate":
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

        likely_causes.append(
            {
                "cause": "DNS resolution problem",
                "reason": reason,
                "confidence": "Possible",
            }
        )

    if likely_causes:
        if apipa_detected or statuses.get("dhcp") == "investigate":
            next_step = (
                "Verify IP configuration and DHCP availability first, then "
                "repeat connectivity and DNS tests."
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
        elif dns_result in {"failed", "timeout", "nxdomain"} or statuses.get("dns") == "investigate":
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

    if any(status == "inconclusive" for status in statuses.values()):
        return {
            "status": "inconclusive",
            "finding": (
                "The available evidence does not establish a network failure, "
                "and some diagnostic results are inconclusive."
            ),
            "likely_causes": [],
            "supporting_findings": supporting_findings,
            "next_step": (
                "Collect the missing evidence and repeat the inconclusive "
                "diagnostics."
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
