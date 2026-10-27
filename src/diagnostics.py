import ipaddress

def analyze_dhcp(data: dict) -> dict:
    """Check workstation evidence for signs of a DHCP problem."""

    ip = data.get("ip_address")
    gateway = data.get("default_gateway")
    dhcp_server = data.get("dhcp_server")

    if not ip:
        return {
            "status": "inconclusive",
            "finding": "No IP address was provided.",
            "next_step": "Check the workstation's IP configuration.",
        }

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "status": "inconclusive",
            "finding": "The IP address is invalid.",
            "next_step": "Check the workstation's IP configuration.",
        }

    if address.version != 4:
        return {
            "status": "inconclusive",
            "finding": "This check only covers IPv4.",
            "next_step": "Collect the workstation's IPv4 configuration.",
        }

    apipa_range = ipaddress.ip_network("169.254.0.0/16")

    # APIPA suggests DHCP may have failed, but doesn't identify the cause.
    if address in apipa_range:
        missing_settings = []

        if not gateway:
            missing_settings.append("default gateway")

        if not dhcp_server:
            missing_settings.append("DHCP server")

        if missing_settings:
            details = " and ".join(missing_settings)

            return {
                "status": "investigate",
                "finding": (
                    "The workstation has an APIPA address, and no "
                    f"{details} was reported. DHCP configuration may "
                    "not have been received."
                ),
                "next_step": (
                    "Check the DHCP client, network connection, and "
                    "DHCP server availability."
                ),
            }

        return {
            "status": "investigate",
            "finding": (
                "The workstation has an APIPA address despite a "
                "reported gateway and DHCP server. Verify the collected "
                "configuration and DHCP lease."
            ),
            "next_step": (
                "Check the DHCP lease details and confirm that the "
                "reported settings belong to this workstation."
            ),
        }

    # A valid-looking IPv4 address doesn't guarantee connectivity.
    return {
        "status": "no_apipa",
        "finding": (
            "The address is outside the APIPA range. "
            "This does not confirm that DHCP or network connectivity "
            "is working correctly."
        ),
        "next_step": "Test gateway connectivity and DNS resolution.",
    }
