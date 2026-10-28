def correlate_findings(results: list[dict]) -> dict:
    """Combine diagnostic reports into an evidence-based assessment."""

    reports = [
        {
            "diagnostic_type": result.get("diagnostic_type", "unknown"),
            "status": result["analysis"]["status"],
            "finding": result["analysis"]["finding"],
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

    likely_causes = []
    dhcp_status = statuses.get("dhcp")
    dns_status = statuses.get("dns")
    connectivity_status = statuses.get("connectivity")

    if dhcp_status == "investigate":
        likely_causes.append(
            {
                "cause": "DHCP or IP configuration problem",
                "reason": (
                    "The DHCP diagnostic identified a condition requiring "
                    "investigation. Resolve the configuration concern before "
                    "assuming higher-level connectivity is healthy."
                ),
                "confidence": "Possible",
            }
        )

    if connectivity_status == "investigate":
        likely_causes.append(
            {
                "cause": "Network connectivity problem",
                "reason": (
                    "The connectivity diagnostic identified a reachability "
                    "problem. Check the gateway and external target results "
                    "to determine where communication is failing."
                ),
                "confidence": "Possible",
            }
        )

    if dns_status == "investigate":
        if connectivity_status == "connected":
            reason = (
                "DNS resolution failed while the gateway and external "
                "connectivity tests succeeded. This makes DNS a priority "
                "for investigation, although those tests do not prove that "
                "the DNS server itself is reachable."
            )
        elif dhcp_status == "investigate":
            reason = (
                "DNS resolution failed, and DHCP or IP configuration also "
                "requires investigation. Verify network configuration and "
                "DNS server settings before isolating the DNS service."
            )
        else:
            reason = (
                "The DNS diagnostic identified a resolution problem. Check "
                "the configured DNS server, the hostname, and the query "
                "response to narrow down the cause."
            )

        likely_causes.append(
            {
                "cause": "DNS resolution problem",
                "reason": reason,
                "confidence": "Possible",
            }
        )

    if likely_causes:
        if dhcp_status == "investigate":
            next_step = (
                "Investigate DHCP and IP configuration first, then repeat "
                "the connectivity and DNS tests."
            )
        elif connectivity_status == "investigate":
            next_step = (
                "Investigate the failed connectivity path before determining "
                "whether DNS or another service is also affected."
            )
        elif dns_status == "investigate":
            next_step = (
                "Inspect the DNS response and test reachability to the "
                "configured DNS server."
            )
        else:
            next_step = (
                "Investigate the listed causes using the supporting findings "
                "and recommended diagnostic tests."
            )

        return {
            "status": "investigate",
            "finding": (
                "The diagnostic results identify one or more failure areas "
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
