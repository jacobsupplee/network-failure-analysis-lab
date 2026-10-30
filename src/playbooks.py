PLAYBOOKS = {
    "DHCP / APIPA failure": {
        "trigger": "The workstation has an IPv4 address in the 169.254.0.0/16 APIPA range, or DHCP configuration is missing.",
        "purpose": "Determine whether the client failed to obtain a usable DHCP lease and isolate whether the issue is local, network-side, or server-side.",
        "safety": "The commands below collect information only. Do not release or renew a lease until you have confirmed the impact and have authorization.",
        "steps": [
            {
                "title": "Confirm the adapter and link state",
                "purpose": "Make sure the affected adapter is enabled and connected to the expected wired or wireless network.",
                "command": "Get-NetAdapter | Format-Table Name, Status, LinkSpeed",
                "expected": "The intended adapter is present and its status is Up.",
                "interpretation": "A disconnected or disabled adapter points to a local link, cable, Wi-Fi, or adapter issue. An Up state does not prove DHCP is working.",
            },
            {
                "title": "Inspect the complete IPv4 and DHCP configuration",
                "purpose": "Check the assigned address, DHCP status, DHCP server, lease, gateway, and DNS servers.",
                "command": "ipconfig /all",
                "expected": "The adapter has an address from the intended subnet, DHCP is enabled when expected, and a DHCP server and default gateway are reported.",
                "interpretation": "An address beginning with 169.254, with no usable gateway or DHCP server, is consistent with a failed DHCP lease. It does not identify the failing component.",
            },
            {
                "title": "Check the DHCP Client service",
                "purpose": "Verify that the Windows DHCP Client service is running.",
                "command": "Get-Service -Name Dhcp",
                "expected": "The service status is Running.",
                "interpretation": "If the service is stopped or unavailable, investigate the local service state and relevant system events before changing configuration.",
            },
            {
                "title": "Review DHCP client events",
                "purpose": "Look for lease acquisition, renewal, or communication errors around the reported incident time.",
                "command": "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-DHCP-Client'; StartTime=(Get-Date).AddHours(-4)} -ErrorAction SilentlyContinue | Select-Object -First 20 TimeCreated, Id, LevelDisplayName, Message",
                "expected": "Events provide context for whether lease discovery, offer, request, or renewal failed.",
                "interpretation": "Correlate event timestamps with the incident. An empty result is not proof that DHCP is healthy; the relevant events may be outside the time window or unavailable.",
            },
            {
                "title": "Verify the DHCP server and scope",
                "purpose": "If you administer the DHCP service, check server availability, scope utilization, exclusions, and reservations. Otherwise, escalate these checks to the network administrator.",
                "command": "Run on the DHCP server: Get-DhcpServerv4Scope | Select-Object ScopeId, State, StartRange, EndRange",
                "expected": "The relevant scope is active and has available addresses for the client subnet.",
                "interpretation": "A stopped service, inactive scope, exhausted pool, or incorrect VLAN/relay path can prevent clients from receiving leases. The server-side command requires the DHCP Server PowerShell module and appropriate privileges.",
            },
        ],
        "remediation": [
            "Confirm the client is connected to the correct VLAN or wireless network.",
            "Check switch-port configuration, DHCP relay/IP helper configuration, and network path to the DHCP server.",
            "Have the DHCP administrator verify service health, scope state, available leases, exclusions, and reservations.",
            "Only after documenting the current configuration and obtaining authorization, consider renewing the client lease with ipconfig /renew.",
        ],
        "closure": [
            "The client receives a valid address from the intended subnet.",
            "The expected DHCP server and default gateway are present.",
            "The client can reach its default gateway.",
            "DNS resolution and access to the original network resource work as expected.",
        ],
    },
    "DNS resolution failure": {
        "trigger": "A hostname lookup returns a timeout, failure, or NXDOMAIN response, or a user cannot reach a resource by name.",
        "purpose": "Separate client resolver configuration, DNS server reachability, and hostname/record problems.",
        "safety": "These steps are read-only. Do not change DNS server settings or flush caches until you have recorded the current configuration and confirmed the intended DNS design.",
        "steps": [
            {
                "title": "Record the configured DNS servers",
                "purpose": "Identify which DNS servers the affected adapter is using.",
                "command": "Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, ServerAddresses",
                "expected": "The active adapter lists the DNS servers expected for that network.",
                "interpretation": "Unexpected, stale, or missing DNS server addresses suggest a client configuration or DHCP option issue.",
            },
            {
                "title": "Query the hostname using the configured resolver",
                "purpose": "Capture the response code, responding DNS server, and returned address.",
                "command": "nslookup <hostname>",
                "expected": "The hostname resolves to the expected address and the responding server is the expected resolver.",
                "interpretation": "A timeout suggests the resolver did not respond. NXDOMAIN means the queried name was not found by that DNS server; confirm spelling, DNS suffix, and whether the record should exist.",
            },
            {
                "title": "Compare with a known-good DNS server",
                "purpose": "Determine whether the failure is specific to the configured resolver or the name itself.",
                "command": "nslookup <hostname> <known-good-dns-server>",
                "expected": "The query succeeds against a resolver authoritative for or able to resolve the target name.",
                "interpretation": "If one resolver succeeds and the configured resolver fails, investigate the configured resolver, forwarding, replication, or policy. Use an approved resolver for the environment.",
            },
            {
                "title": "Test reachability to the configured DNS server",
                "purpose": "Check whether the DNS server is reachable over the network.",
                "command": "Test-NetConnection <dns-server-ip> -Port 53",
                "expected": "TcpTestSucceeded is True when the server accepts TCP DNS on port 53.",
                "interpretation": "A failed TCP test does not prove all DNS traffic is blocked because DNS commonly uses UDP as well. Review routing and firewall evidence and test the actual DNS query.",
            },
            {
                "title": "Check the local DNS cache",
                "purpose": "Inspect cached records that may affect the result.",
                "command": "ipconfig /displaydns",
                "expected": "Cached entries are consistent with the expected name-to-address mapping and TTL.",
                "interpretation": "A stale or unexpected cached entry may contribute to a client-only issue. Record the current state before considering a cache flush.",
            },
        ],
        "remediation": [
            "Correct an incorrect DNS server assignment through the approved DHCP or static configuration process.",
            "If only one resolver fails, investigate its service, forwarding, replication, and network access.",
            "If the response is NXDOMAIN, verify the exact hostname, DNS suffix, zone, and record with the DNS administrator.",
            "Only after recording evidence and obtaining authorization, consider clearing the local resolver cache with ipconfig /flushdns.",
        ],
        "closure": [
            "The hostname resolves through the intended DNS server.",
            "The returned address matches the expected record for the environment.",
            "The original application or network resource is reachable by hostname.",
        ],
    },
    "Default gateway / routing failure": {
        "trigger": "The default route is missing, the reported gateway differs from the route table, or traffic to off-subnet destinations fails.",
        "purpose": "Verify the active adapter's gateway configuration and determine whether Windows has a usable route to the destination.",
        "safety": "These commands inspect state only. Do not add, delete, or modify routes without confirming the intended topology and obtaining authorization.",
        "steps": [
            {
                "title": "Inspect adapter addressing and gateway",
                "purpose": "Record the IPv4 address, subnet mask, and configured default gateway.",
                "command": "ipconfig /all",
                "expected": "The active adapter has the expected address, subnet, and default gateway for its VLAN.",
                "interpretation": "A missing or unexpected gateway may indicate DHCP option, static configuration, or adapter-selection issues.",
            },
            {
                "title": "Inspect the IPv4 routing table",
                "purpose": "Check for a default route and identify its gateway, interface, and metric.",
                "command": "route print -4",
                "expected": "An appropriate 0.0.0.0/0 route exists for off-subnet traffic and uses the expected gateway and interface.",
                "interpretation": "No default route can prevent access to off-subnet destinations. Multiple default routes require reviewing interface and route metrics; the lowest route metric alone does not establish the final selection.",
            },
            {
                "title": "Inspect the selected route to a destination",
                "purpose": "Ask Windows which route it would use for a specific destination.",
                "command": "Find-NetRoute -RemoteIPAddress <destination-ip>",
                "expected": "The selected route uses the expected interface and next-hop gateway.",
                "interpretation": "An unexpected interface or next hop can indicate competing routes, VPN software, interface metrics, or an incorrect route.",
            },
            {
                "title": "Test the local gateway",
                "purpose": "Check basic IP reachability to the configured gateway.",
                "command": "Test-Connection <default-gateway-ip> -Count 4",
                "expected": "Replies are received from the gateway when ICMP is permitted.",
                "interpretation": "No reply may indicate a local link, VLAN, gateway, or ICMP policy issue. Some gateways block ICMP, so corroborate with other evidence.",
            },
            {
                "title": "Trace the path to the affected destination",
                "purpose": "Identify where replies stop along the path, where routers respond.",
                "command": "tracert -d <destination-ip>",
                "expected": "The trace progresses through expected network hops toward the destination.",
                "interpretation": "Asterisks do not necessarily mean forwarding failed; intermediate devices may filter or rate-limit TTL-expired responses.",
            },
        ],
        "remediation": [
            "Verify the workstation is connected to the intended network or VLAN.",
            "Compare the adapter gateway with the active default route and identify competing VPN or virtual-network routes.",
            "Have the network administrator verify gateway availability, switch VLAN assignment, and upstream routing.",
            "Only change route or gateway settings after confirming the intended network design and documenting the existing route table.",
        ],
        "closure": [
            "The active adapter has the expected address, subnet, and gateway.",
            "Windows selects the expected route and interface for the affected destination.",
            "Gateway and destination connectivity tests succeed, or any ICMP filtering is independently accounted for.",
            "The original application or network resource is reachable.",
        ],
    },
}


def get_playbook(name: str) -> dict:
    """Return a troubleshooting playbook by its display name."""
    if name not in PLAYBOOKS:
        raise KeyError(f"Unknown troubleshooting playbook: {name}")
    return PLAYBOOKS[name]


def list_playbooks() -> list[str]:
    """Return available troubleshooting playbook names."""
    return list(PLAYBOOKS)
