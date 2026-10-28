"""Evidence normalization, conflict detection, and source references for correlation."""


def normalize_evidence(evidence) -> dict:
    if isinstance(evidence, dict):
        return evidence
    normalized = {}
    if isinstance(evidence, list):
        for item in evidence:
            if not isinstance(item, dict):
                continue
            label = item.get("observation", item.get("item", item.get("check", "")))
            value = item.get("result", item.get("value"))
            if label:
                normalized[label] = value
    return normalized


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


def normalize_dns_result(value) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized in {"success", "successful", "resolved", "passed"}:
        return "success"
    if normalized in {"failed", "failure", "timeout", "nxdomain", "error"}:
        return normalized
    return normalized or None


def detect_conflicts(reports: list[dict]) -> tuple:
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

    dns_observations = []

    for report in reports:
        if report["diagnostic_type"] != "dns":
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
            items = []

        for item in items:
            if not isinstance(item, dict):
                continue

            label = str(
                item.get(
                    "observation",
                    item.get("item", item.get("check", "")),
                )
            ).strip().lower().replace("_", " ")

            if label != "resolution result":
                continue

            value = normalize_dns_result(
                item.get("result", item.get("value"))
            )
            if value is not None:
                dns_observations.append(value)

    dns_success_detected = "success" in dns_observations
    dns_failure_detected = any(
        value != "success" for value in dns_observations
    )
    dns_conflict = dns_success_detected and dns_failure_detected

    if dns_conflict:
        conflicts.append(
            {
                "type": "contradictory_evidence",
                "description": (
                    "DNS resolution results conflict: some observations "
                    "report successful resolution while others report failure. "
                    "Repeat the DNS test under the same conditions and compare "
                    "the target hostname, DNS server, and timestamps."
                ),
            }
        )

    external_observations = []

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
            items = []

        for item in items:
            if not isinstance(item, dict):
                continue

            label = str(
                item.get(
                    "observation",
                    item.get("item", item.get("check", "")),
                )
            ).strip().lower().replace("_", " ")

            if label not in {
                "external reachability",
                "external target reachable",
                "external reachable",
            }:
                continue

            value = is_reachable(item.get("result", item.get("value")))
            if value is not None:
                external_observations.append(value)

    external_conflict = (
        True in external_observations
        and False in external_observations
    )

    if external_conflict:
        conflicts.append(
            {
                "type": "contradictory_evidence",
                "description": (
                    "External connectivity results conflict: some observations "
                    "report the external target as reachable while others report "
                    "it as unreachable. Repeat the test using the same target "
                    "and compare timestamps and network conditions."
                ),
            }
        )

    default_route_observations = []

    for report in reports:
        if report["diagnostic_type"] != "routing":
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
            items = []

        for item in items:
            if not isinstance(item, dict):
                continue

            label = str(
                item.get(
                    "observation",
                    item.get("item", item.get("check", "")),
                )
            ).strip().lower().replace("_", " ")

            if label not in {"default route count", "default routes count"}:
                continue

            value = item.get("result", item.get("value"))
            if isinstance(value, int) and not isinstance(value, bool):
                default_route_observations.append(value)
            elif isinstance(value, str) and value.strip().isdigit():
                default_route_observations.append(int(value.strip()))

    routing_conflict = (
        any(value == 0 for value in default_route_observations)
        and any(value > 0 for value in default_route_observations)
    )

    if routing_conflict:
        conflicts.append(
            {
                "type": "contradictory_evidence",
                "description": (
                    "Routing results conflict: some reports indicate no IPv4 "
                    "default route while others indicate at least one. Repeat "
                    "the route-table collection and compare the captured results."
                ),
            }
        )
    return conflicts, gateway_conflict, dns_conflict, external_conflict, routing_conflict, dns_observations


def build_evidence_references(cause: dict, reports: list[dict]) -> list[dict]:
    """Link a likely cause to original report observations that support it."""
    cause_name = cause.get("cause", "")
    if cause_name == "Missing IPv4 default route":
        diagnostic_types, label_terms = {"routing"}, ("default route",)
    elif cause_name == "DHCP or IP configuration problem":
        diagnostic_types, label_terms = {"dhcp"}, ("ip address", "ipv4 address", "dhcp")
    elif cause_name == "Local network or default gateway reachability problem":
        diagnostic_types, label_terms = {"connectivity"}, ("gateway",)
    elif cause_name == "External network reachability problem":
        diagnostic_types, label_terms = {"connectivity", "ports"}, ("gateway", "external", "tcp connection result")
    elif cause_name == "DNS resolution problem":
        diagnostic_types, label_terms = {"dns"}, ("resolution result", "dns server", "hostname")
    elif cause_name in {
        "TCP target or network path unavailable",
        "TCP service unavailable or connection actively rejected",
        "TCP port-specific connectivity problem",
    }:
        diagnostic_types, label_terms = {"ports"}, ("tcp connection result", "target host", "target port")
    else:
        diagnostic_types, label_terms = {"connectivity"}, ("gateway", "external")
    references = []
    for report in reports:
        if report["diagnostic_type"] not in diagnostic_types:
            continue
        evidence = report.get("evidence", [])
        if isinstance(evidence, dict):
            items = [{"observation": label, "result": value} for label, value in evidence.items()]
        elif isinstance(evidence, list):
            items = evidence
        else:
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            label = item.get("observation", item.get("item", item.get("check", "")))
            value = item.get("result", item.get("value"))
            normalized_label = str(label).strip().lower().replace("_", " ")
            if not label or not any(term in normalized_label for term in label_terms):
                continue
            references.append({
                "report_index": report["report_index"],
                "diagnostic_type": report["diagnostic_type"],
                "finding": report["finding"],
                "observation": label,
                "value": value,
            })
    return references
