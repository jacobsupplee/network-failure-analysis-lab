from src.diagnostics import build_report

def analyze_dns(data: dict) -> dict:
    """Evaluate supplied evidence for a DNS resolution problem."""

    hostname = data.get("hostname")
    dns_server = data.get("dns_server")
    resolution_result = data.get("resolution_result")

    evidence = [
        {"observation": "Hostname", "result": hostname or "Not provided"},
        {"observation": "DNS server", "result": dns_server or "Not provided"},
        {"observation": "Resolution result", "result": resolution_result or "Not tested"},
    ]

    if not hostname or not resolution_result:
        return build_report(
            "inconclusive",
            "Insufficient evidence to evaluate DNS resolution.",
            "Collect a hostname and test its DNS resolution.",
            evidence,
            [],
            [{"test": "Run nslookup <hostname>", "purpose": "Check whether the hostname resolves and which DNS server responds."}],
            [
                "Confirm the hostname resolves to the expected address.",
                "Confirm the intended network resource is reachable.",
            ],
        )

    normalized_result = resolution_result.strip().lower()

    if normalized_result in {"failed", "timeout", "nxdomain"}:
        return build_report(
            "investigate",
            f"DNS resolution for {hostname} did not succeed (result: {normalized_result}).",
            "Check DNS server reachability and the hostname's DNS records.",
            evidence,
            [
                {
                    "cause": "DNS server unavailable or unresponsive",
                    "reason": "The DNS query may not be receiving a usable response.",
                    "confidence": "Possible",
                },
                {
                    "cause": "Hostname or DNS record issue",
                    "reason": "The hostname may be incorrect or lack the expected record.",
                    "confidence": "Possible",
                },
            ],
            [
                {"test": f"Run nslookup {hostname}", "purpose": "Inspect the DNS response and responding server."},
                {"test": "Test connectivity to the configured DNS server", "purpose": "Determine whether the server is reachable."},
            ],
            [
                "Confirm the hostname resolves to the expected address.",
                "Retry access to the original network resource.",
            ],
        )

    if normalized_result == "success":
        return build_report(
            "resolved",
            f"DNS resolution for {hostname} succeeded in the supplied evidence.",
            "If access still fails, test connectivity and the target service.",
            evidence,
            [],
            [{"test": "Test connectivity to the resolved address", "purpose": "Check whether the issue occurs after name resolution."}],
            [
                "Confirm the resolved address is expected.",
                "Confirm the intended network service is accessible.",
            ],
        )

    return build_report(
        "inconclusive",
        f"Unrecognized DNS test result: {resolution_result}.",
        "Use a supported result: success, failed, timeout, or nxdomain.",
        evidence,
        [],
        [{"test": f"Run nslookup {hostname}", "purpose": "Collect a recognizable DNS resolution result."}],
        [
            "Record the DNS response accurately.",
            "Confirm the expected hostname and address.",
        ],
    )
