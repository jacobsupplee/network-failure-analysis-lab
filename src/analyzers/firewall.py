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
