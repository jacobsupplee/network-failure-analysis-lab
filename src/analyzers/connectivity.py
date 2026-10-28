import ipaddress

from src.diagnostics import build_report

def analyze_connectivity(data: dict) -> dict:
    """Analyze gateway and external connectivity evidence."""

    gateway_result = data.get("gateway_reachable")
    external_result = data.get("external_reachable")
    gateway_ip = data.get("default_gateway")
    external_target = data.get("external_target")

    evidence = [
        {"item": "Default gateway", "value": gateway_ip or "Not reported"},
        {
            "item": "Gateway reachability",
            "value": "Reachable" if gateway_result is True else "Unreachable" if gateway_result is False else "Not tested",
        },
        {"item": "External target", "value": external_target or "Not reported"},
        {
            "item": "External reachability",
            "value": "Reachable" if external_result is True else "Unreachable" if external_result is False else "Not tested",
        },
    ]

    if gateway_ip:
        try:
            ipaddress.ip_address(gateway_ip)
        except ValueError:
            return build_report(
                status="inconclusive",
                finding="The reported default gateway is not a valid IP address.",
                next_step="Verify the workstation's network configuration.",
                evidence=evidence,
                hypotheses=[
                    {
                        "cause": "Invalid gateway evidence",
                        "reason": "The reported gateway could not be validated as an IP address.",
                        "confidence": "High",
                    }
                ],
                next_tests=[
                    {
                        "test": "Inspect the workstation's IP configuration",
                        "purpose": "Confirm the actual default gateway.",
                    }
                ],
                verification=["Confirm the default gateway in the operating system."],
            )

    if gateway_result is None or external_result is None:
        return build_report(
            status="inconclusive",
            finding="There is not enough reachability evidence to assess connectivity.",
            next_step="Run the gateway and external connectivity tests.",
            evidence=evidence,
            hypotheses=[],
            next_tests=[
                {
                    "test": "Test default gateway reachability",
                    "purpose": "Check whether the workstation can reach its local gateway.",
                },
                {
                    "test": "Test external target reachability",
                    "purpose": "Check connectivity beyond the local network.",
                },
            ],
            verification=["Confirm both connectivity tests completed."],
        )

    if gateway_result is False:
        finding = (
            "The default gateway did not respond to the reachability test. "
            "This may indicate a local connectivity issue, but ICMP filtering "
            "can also cause this result."
        )
        status = "investigate"
        next_step = "Verify local connectivity and gateway configuration."
        hypotheses = [
            {
                "cause": "Local network connectivity issue",
                "reason": "The gateway did not respond to the reachability test.",
                "confidence": "Medium",
            }
        ]
    elif external_result is False:
        finding = (
            "The gateway responded, but the external target did not. "
            "This suggests a possible issue beyond the workstation's "
            "local gateway, although the target may filter ICMP."
        )
        status = "investigate"
        next_step = "Check external routing, firewall policy, and the target's reachability."
        hypotheses = [
            {
                "cause": "External connectivity or filtering issue",
                "reason": "The gateway responded, but the external target did not.",
                "confidence": "Medium",
            }
        ]
    else:
        finding = (
            "The gateway and external target responded to the reachability "
            "tests. This does not guarantee that DNS or application services work."
        )
        status = "connected"
        next_step = "If users still experience failures, test DNS and the affected service."
        hypotheses = []

    return build_report(
        status=status,
        finding=finding,
        next_step=next_step,
        evidence=evidence,
        hypotheses=hypotheses,
        next_tests=[
            {
                "test": "Check the route to the destination",
                "purpose": "Investigate the path traffic takes toward the external target.",
            },
            {
                "test": "Test the affected application or service",
                "purpose": "Determine whether the issue is limited to a particular service.",
            },
        ],
        verification=[
            "Confirm connectivity results using an additional test when necessary."
        ],
    )
