import ipaddress

def analyze_dhcp(data: dict) -> dict:
    """Check for signs of a DHCP configuration problem."""

    ip = data.get("ip_address")

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

    # An APIPA address suggests DHCP may have failed, but doesn't explain why.
    if address in apipa_range:
        return {
            "status": "investigate",
            "finding": (
                "The workstation has an APIPA address. "
                "It may not have received its DHCP configuration."
            ),
            "next_step": "Check DHCP connectivity and client settings.",
        }

    # A normal-looking address doesn't guarantee the network is working.
    return {
        "status": "no_apipa",
        "finding": (
            "The address is outside the APIPA range. "
            "This does not confirm that the network is working."
        ),
        "next_step": "Check gateway connectivity and DNS resolution.",
    }
