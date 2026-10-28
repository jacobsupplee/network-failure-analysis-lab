import ipaddress

from src.diagnostics import build_report

def analyze_dhcp(data: dict) -> dict:
    """Check workstation evidence for signs of a DHCP problem."""

    ip = data.get("ip_address")
    gateway = data.get("default_gateway")
    dhcp_server = data.get("dhcp_server")

    if not ip:
        return build_report(
            "inconclusive",
            "No IP address was provided.",
            "Collect the workstation's IPv4 configuration.",
            [{"observation": "IP address", "result": "Not provided"}],
            [],
            [{"test": "Run ipconfig /all", "purpose": "Collect IP, gateway, and DHCP details."}],
            ["Confirm that the workstation has a valid IPv4 configuration."],
        )

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return build_report(
            "inconclusive",
            "The IP address is invalid.",
            "Check the workstation's IP configuration.",
            [{"observation": "IP address", "result": "Invalid value"}],
            [],
            [{"test": "Run ipconfig /all", "purpose": "Collect the actual assigned address."}],
            ["Confirm that the collected address is valid IPv4."],
        )

    if address.version != 4:
        return build_report(
            "inconclusive",
            "This check only covers IPv4.",
            "Collect the workstation's IPv4 configuration.",
            [{"observation": "IP address", "result": "IPv6 address"}],
            [],
            [{"test": "Run ipconfig /all", "purpose": "Collect IPv4 configuration details."}],
            ["Confirm the workstation's IPv4 address and DHCP settings."],
        )

    apipa_range = ipaddress.ip_network("169.254.0.0/16")

    evidence = [
        {
            "observation": "IPv4 address",
            "result": str(address),
            "interpretation": (
                "Address is in the APIPA range."
                if address in apipa_range
                else "Address is outside the APIPA range."
            ),
        },
        {
            "observation": "Default gateway",
            "result": str(gateway) if gateway else "Not reported",
        },
        {
            "observation": "DHCP server",
            "result": str(dhcp_server) if dhcp_server else "Not reported",
        },
    ]

    if address in apipa_range:
        missing_settings = []

        if not gateway:
            missing_settings.append("default gateway")

        if not dhcp_server:
            missing_settings.append("DHCP server")

        if missing_settings:
            finding = (
                "The workstation has an APIPA address, and no "
                f"{' and '.join(missing_settings)} was reported. "
                "DHCP configuration may not have been received."
            )

            hypotheses = [
                {
                    "cause": "DHCP server unavailable or unreachable",
                    "reason": "The workstation may not be receiving a DHCP lease.",
                    "confidence": "Possible",
                },
                {
                    "cause": "Client or network configuration issue",
                    "reason": "The client may be unable to reach the DHCP service.",
                    "confidence": "Possible",
                },
            ]

            next_tests = [
                {
                    "test": "Check the network adapter and link state",
                    "purpose": "Confirm the workstation has an active network connection.",
                },
                {
                    "test": "Run ipconfig /all",
                    "purpose": "Check DHCP enabled status, address details, and lease information.",
                },
                {
                    "test": "Inspect DHCP server availability and scope",
                    "purpose": "Check whether the server is reachable and has addresses available.",
                },
            ]

            return build_report(
                "investigate",
                finding,
                "Check the DHCP client, network connection, and DHCP server availability.",
                evidence,
                hypotheses,
                next_tests,
                [
                    "The workstation receives an address from the intended subnet.",
                    "A valid default gateway and DHCP lease are present.",
                    "The workstation can reach its gateway and resolve DNS names.",
                ],
            )

        return build_report(
            "investigate",
            (
                "The workstation has an APIPA address despite a reported "
                "gateway and DHCP server. Verify the collected configuration."
            ),
            "Check the DHCP lease details and confirm the settings belong to this workstation.",
            evidence,
            [
                {
                    "cause": "Stale or inconsistent configuration evidence",
                    "reason": "The reported gateway and DHCP server do not establish that a valid lease exists.",
                    "confidence": "Possible",
                }
            ],
            [
                {
                    "test": "Run ipconfig /all",
                    "purpose": "Confirm the current address, DHCP server, and lease details.",
                },
                {
                    "test": "Review DHCP client events",
                    "purpose": "Look for lease acquisition errors or renewal failures.",
                },
            ],
            [
                "Confirm a valid address and lease from the intended DHCP scope.",
                "Test gateway connectivity and DNS resolution.",
            ],
        )

    return build_report(
        "no_apipa",
        (
            "The address is outside the APIPA range. This does not confirm "
            "that DHCP or network connectivity is working correctly."
        ),
        "Test gateway connectivity and DNS resolution.",
        evidence,
        [
            {
                "cause": "Connectivity or DNS issue may still exist",
                "reason": "A non-APIPA address alone does not prove end-to-end connectivity.",
                "confidence": "Unconfirmed",
            }
        ],
        [
            {
                "test": "Ping the default gateway",
                "purpose": "Test basic reachability to the local gateway.",
            },
            {
                "test": "Resolve a known DNS hostname",
                "purpose": "Check whether DNS resolution works.",
            },
        ],
        [
            "Confirm gateway reachability.",
            "Confirm DNS resolution.",
            "Test access to the intended network resource.",
        ],
    )
