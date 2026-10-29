from src.diagnostics import build_report


EXPECTED_PROFILES = {"Domain", "Private", "Public"}


def analyze_firewall(data: dict) -> dict:
    """Assess Windows Firewall profile settings without claiming a block occurred."""
    profiles = data.get("profiles")

    if not isinstance(profiles, list) or not profiles:
        return build_report(
            "inconclusive",
            "Windows Firewall profile data is unavailable or incomplete.",
            "Run the scan on Windows and verify that PowerShell can read firewall profiles.",
            [],
            [],
            [{"test": "Inspect Windows Firewall profiles", "purpose": "Collect enabled-state data for Domain, Private, and Public profiles."}],
            ["Repeat the firewall profile collection and confirm that all three profiles are reported."],
        )

    evidence = []
    valid_profiles = {}
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        name = profile.get("name")
        enabled = profile.get("enabled")
        if isinstance(name, str) and name in EXPECTED_PROFILES:
            valid_profiles[name] = enabled
            evidence.append({
                "profile": name,
                "enabled": enabled,
                "observation": (
                    "Profile is enabled." if enabled is True
                    else "Profile is disabled." if enabled is False
                    else "Profile enabled state could not be determined."
                ),
            })

    missing = sorted(EXPECTED_PROFILES - valid_profiles.keys())
    unknown_states = sorted(
        name for name, enabled in valid_profiles.items()
        if not isinstance(enabled, bool)
    )
    disabled = sorted(
        name for name, enabled in valid_profiles.items()
        if enabled is False
    )

    if not valid_profiles or missing or unknown_states:
        reasons = []
        if missing:
            reasons.append("Missing profiles: " + ", ".join(missing) + ".")
        if unknown_states:
            reasons.append("Unknown enabled state for: " + ", ".join(unknown_states) + ".")
        finding = "Firewall profile assessment is incomplete. " + " ".join(reasons)
        return build_report(
            "inconclusive",
            finding,
            "Repeat collection and confirm the Domain, Private, and Public profile states before drawing conclusions.",
            evidence,
            [],
            [{"test": "Recheck firewall profile data", "purpose": "Confirm that all expected profiles and their enabled states are available."}],
            ["Verify that Domain, Private, and Public profiles each report a Boolean enabled state."],
        )

    if disabled:
        return build_report(
            "investigate",
            "One or more Windows Firewall profiles are disabled: " + ", ".join(disabled) + ".",
            "Confirm which network profile is active and review the organization's firewall policy before changing settings.",
            evidence,
            [{
                "cause": "Windows Firewall protection may be disabled for a network profile",
                "reason": "A disabled profile can reduce host firewall protection. This observation does not establish whether it caused a particular connection failure.",
                "confidence": "High for the profile state; unconfirmed as a cause of connectivity failure",
            }],
            [{"test": "Identify the active network profile", "purpose": "Determine whether the current connection uses Domain, Private, or Public settings."},
             {"test": "Review firewall policy and relevant rules", "purpose": "Check policy and connection-specific rules without assuming the profile state alone explains a failed connection."}],
            ["Confirm the active network profile and review the applicable firewall policy."],
        )

    return build_report(
        "healthy",
        "Domain, Private, and Public Windows Firewall profiles are enabled.",
        "No profile-level change is indicated by this check. If a connection still fails, inspect the relevant rules and compare with the TCP test.",
        evidence,
        [],
        [{"test": "Review connection-specific firewall rules if needed", "purpose": "Profile status alone does not show whether a specific connection is allowed or blocked."}],
        ["Confirm all three profile states and retest the affected connection."],
    )


def _filter_values(value):
    return {part.strip().lower() for part in str(value or "Any").split(",") if part.strip()} or {"any"}


def _port_filter_matches(value, port):
    values = _filter_values(value)
    if values & {"any", "*"}:
        return True
    for item in values:
        if item.isdigit() and int(item) == port:
            return True
        if "-" in item:
            try:
                low, high = (int(part.strip()) for part in item.split("-", 1))
                if low <= port <= high:
                    return True
            except ValueError:
                continue
    return False


def _address_filter_matches(value, target_ip):
    values = _filter_values(value)
    if values & {"any", "*"}:
        return True
    import ipaddress
    try:
        target = ipaddress.ip_address(str(target_ip))
    except ValueError:
        return False
    for item in values:
        try:
            if target in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            try:
                low, high = (ipaddress.ip_address(part.strip()) for part in item.split("-", 1))
                if low <= target <= high:
                    return True
            except ValueError:
                continue
    return False


def analyze_firewall_rules(data: dict) -> dict:
    """Find outbound block rules whose collected target filters may overlap."""
    rules = data.get("candidate_rules")
    port = data.get("target_port")
    target_ip = data.get("target_ip") or data.get("target_host")
    if not isinstance(rules, list) or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return build_report("inconclusive", "Outbound firewall rule data is unavailable or invalid.",
            "Repeat the scan and verify PowerShell access to active outbound firewall rules.", [], [], [], [])

    matches = []
    for rule in rules:
        if not isinstance(rule, dict) or str(rule.get("action", "")).lower() != "block":
            continue
        protocols = _filter_values(rule.get("protocol", "Any"))
        if not (protocols & {"any", "*", "6", "tcp"}):
            continue
        if not _port_filter_matches(rule.get("remote_port", "Any"), port):
            continue
        if not _address_filter_matches(rule.get("remote_address", "Any"), target_ip):
            continue
        matches.append({"rule": rule.get("display_name") or "Unnamed outbound block rule",
            "action": "block", "profile": rule.get("profile", "Any"), "protocol": rule.get("protocol", "Any"),
            "remote_port": rule.get("remote_port", "Any"), "remote_address": rule.get("remote_address", "Any"),
            "program": rule.get("program", "Any"), "service": rule.get("service", "Any")})

    if matches:
        return build_report("investigate", f"{len(matches)} enabled outbound block rule(s) may match {target_ip}:{port}.",
            "Review each rule’s profile, application/service filters, policy source, and precedence before changing policy.",
            matches, [{"cause": "An outbound Windows Firewall block rule may apply to the target connection",
            "reason": "Address, protocol, and port filters overlap the target. This is a candidate match, not proof that the rule blocked the connection; profile, program/service, and precedence are not fully simulated.",
            "confidence": "Moderate for filter overlap; unconfirmed as the cause of the connection result"}],
            [{"test": "Inspect the candidate outbound block rule", "purpose": "Compare profile, program/service restrictions, and policy precedence with the affected connection."}],
            ["Verify rule scope and active profile, then retest the target connection."])

    return build_report("healthy", f"No matching outbound block rule was found in collected filters for {target_ip}:{port}.",
        "If the connection still fails, inspect application-specific restrictions, endpoint security, and upstream network controls.",
        [{"target": f"{target_ip}:{port}", "candidate_rules_checked": len(rules), "matching_block_rules": 0}], [],
        [{"test": "Check other policy layers if connectivity still fails", "purpose": "This review does not fully simulate Windows Firewall policy precedence or every application/service constraint."}],
        ["Retest the TCP connection and correlate it with the firewall rule evidence."])
