from pathlib import Path

import streamlit as st

from src.analyzers.connectivity import analyze_connectivity
from src.analyzers.dhcp import analyze_dhcp
from src.analyzers.firewall import analyze_firewall, analyze_firewall_rules
from src.analyzers.dns import analyze_dns
from src.analyzers.ports import analyze_port
from src.analyzers.routing import analyze_routing
from src.analysis_runner import run_analysis
from src.correlation import correlate_findings
from src.diagnostics import build_report
from src.diagnostic_report import build_diagnostic_report_html, build_diagnostic_report_json
from src.evidence_collection import (
    collect_connectivity,
    collect_dns_resolution,
    collect_firewall_profiles,
    collect_firewall_rules,
    collect_network_configuration,
    collect_routing_table,
    collect_tcp_connection,
)
from src.scan_history import (
    clear_scan_history,
    compare_scans,
    load_scan_history,
    save_scan,
)
from src.network_baseline import (
    clear_baseline,
    compare_configuration,
    load_baseline,
    save_baseline,
)
from src.playbooks import get_playbook, list_playbooks
from src.incidents import (
    add_timeline_entry,
    associate_scan,
    build_incident_report_html,
    create_incident,
    load_incidents,
    update_incident,
)

SCENARIOS = {
    "DHCP diagnostic": Path("scenarios/apipa_dhcp.json"),
    "DNS diagnostic": Path("scenarios/dns_failure.json"),
    "TCP port refused": Path("scenarios/tcp_refused.json"),
    "Missing default route": Path("scenarios/missing_default_route.json"),
    "Default gateway mismatch": Path("scenarios/default_gateway_mismatch.json"),
    "Healthy routing baseline": Path("scenarios/healthy_routing_baseline.json"),
}

STATUS_LABELS = {
    "healthy": "Healthy",
    "no_failure_detected": "No failure detected",
    "resolved": "Resolved",
    "connected": "Connected",
    "reachable": "Reachable",
    "route_present": "Route present",
    "no_apipa": "No APIPA address detected",
    "profiles_enabled": "Firewall profiles enabled",
    "investigate": "Investigation required",
    "inconclusive": "Inconclusive",
}


def status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status.replace("_", " ").capitalize())


def show_status_message(status: str, message: str) -> None:
    if status in {"healthy", "no_failure_detected", "resolved", "connected", "reachable", "route_present", "no_apipa", "profiles_enabled"}:
        st.success(message)
    elif status == "investigate":
        st.warning(message)
    elif status == "inconclusive":
        st.info(message)
    else:
        st.info(message)


def display_analysis(result: dict, live: bool = False) -> None:
    analysis = result["analysis"]
    status = analysis.get("status", "inconclusive")

    st.subheader(result.get("title", "Diagnostic result"))
    show_status_message(status, f"{status_label(status)}: {analysis.get('finding', 'No finding was provided.')}")

    col1, col2 = st.columns(2)
    col1.metric("Severity", analysis.get("severity", "Not specified"))
    col2.write("**Recommended next step**")
    col2.write(analysis.get("next_step", "No next step was provided."))

    with st.expander("Evidence", expanded=False):
        evidence = analysis.get("evidence", [])
        if evidence:
            st.json(evidence)
        else:
            st.write("No evidence was recorded.")

    with st.expander("Possible causes", expanded=False):
        hypotheses = analysis.get("hypotheses", [])
        if hypotheses:
            for hypothesis in hypotheses:
                if isinstance(hypothesis, dict):
                    st.markdown(f"**{hypothesis.get('cause', 'Possible cause')}**")
                    if hypothesis.get("reason"):
                        st.write(hypothesis["reason"])
                    if hypothesis.get("confidence"):
                        st.caption(f"Confidence: {hypothesis['confidence']}")
                else:
                    st.write(hypothesis)
        else:
            st.write("No possible causes were identified.")

    with st.expander("Recommended tests", expanded=False):
        next_tests = analysis.get("next_tests", [])
        if next_tests:
            for test in next_tests:
                if isinstance(test, dict):
                    st.markdown(f"**{test.get('test', 'Recommended test')}**")
                    if test.get("purpose"):
                        st.write(test["purpose"])
                else:
                    st.write(test)
        else:
            st.write("No additional tests were recommended.")

    with st.expander("Verification steps", expanded=False):
        verification = analysis.get("verification", [])
        if verification:
            for step in verification:
                st.markdown(f"- {step}")
        else:
            st.write("No verification steps were recorded.")

    if result.get("details"):
        with st.expander("Raw collection output", expanded=False):
            st.code(result["details"], language="text")

    if not live and "expected_status" in result:
        matches = result["matches_expected"]
        if matches:
            st.success("Scenario expectation matched.")
        else:
            st.warning("Scenario result did not match the expected status.")


def make_live_result(
    scenario_id: str,
    title: str,
    diagnostic_type: str,
    analysis: dict,
    details: str | None = None,
) -> dict:
    result = {
        "scenario_id": scenario_id,
        "title": title,
        "diagnostic_type": diagnostic_type,
        "analysis": analysis,
    }

    if details:
        result["details"] = details

    return result


def make_inconclusive_report(
    finding: str,
    next_step: str,
) -> dict:
    return build_report(
        "inconclusive",
        finding,
        next_step,
        [],
        [],
        [],
        [],
    )


def run_live_scan(
    tcp_host: str = "example.com",
    tcp_port: int = 443,
) -> dict:
    results = []
    adapter = None
    gateway_ip = None
    routing_data = None
    firewall_data = None
    tcp_data = None

    try:
        configuration = collect_network_configuration()
        adapter = configuration.get("primary_adapter")

        if adapter:
            gateway_ip = adapter.get("default_gateway")

        dhcp_evidence = {
            "ip_address": adapter.get("ip_address") if adapter else None,
            "default_gateway": gateway_ip,
            "dhcp_server": adapter.get("dhcp_server") if adapter else None,
        }

        dhcp_analysis = analyze_dhcp(dhcp_evidence)
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        dhcp_analysis = make_inconclusive_report(
            f"Network configuration collection failed: {error}",
            "Check the network configuration command and retry the scan.",
        )

    results.append(
        make_live_result(
            "LIVE-DHCP",
            "Live DHCP and IP Configuration",
            "dhcp",
            dhcp_analysis,
        )
    )

    try:
        dns_data = collect_dns_resolution()
        dns_servers = adapter.get("dns_servers", []) if adapter else []

        dns_evidence = {
            "hostname": dns_data.get("hostname"),
            "dns_server": dns_servers[0] if dns_servers else None,
            "resolution_result": dns_data.get("resolution_result"),
        }

        dns_analysis = analyze_dns(dns_evidence)
        dns_details = dns_data.get("details")
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        dns_analysis = make_inconclusive_report(
            f"DNS collection failed: {error}",
            "Check DNS collection and retry hostname resolution.",
        )
        dns_details = str(error)

    results.append(
        make_live_result(
            "LIVE-DNS",
            "Live DNS Resolution",
            "dns",
            dns_analysis,
            dns_details,
        )
    )

    try:
        connectivity_data = collect_connectivity(gateway_ip)
        connectivity_analysis = analyze_connectivity(connectivity_data)
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        connectivity_analysis = make_inconclusive_report(
            f"Connectivity collection failed: {error}",
            "Check connectivity collection and retry the scan.",
        )

    results.append(
        make_live_result(
            "LIVE-CONNECTIVITY",
            "Live Network Connectivity",
            "connectivity",
            connectivity_analysis,
        )
    )

    try:
        routing_data = collect_routing_table()
        routing_data["default_gateway"] = gateway_ip
        routing_data["destination"] = "1.1.1.1"
        routing_analysis = analyze_routing(routing_data)
        routing_details = routing_data.get("raw_output")
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        routing_analysis = make_inconclusive_report(
            f"Routing table collection failed: {error}",
            "Check the Windows routing table command and retry the scan.",
        )
        routing_details = str(error)

    results.append(
        make_live_result(
            "LIVE-ROUTING",
            "Live Routing Table Analysis",
            "routing",
            routing_analysis,
            routing_details,
        )
    )

    try:
        tcp_data = collect_tcp_connection(tcp_host, tcp_port)
        tcp_analysis = analyze_port(tcp_data)
        tcp_details = tcp_data.get("error")
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        tcp_analysis = make_inconclusive_report(
            f"TCP connection test failed: {error}",
            "Check the target host and port, then retry the TCP test.",
        )
        tcp_details = str(error)

    results.append(
        make_live_result(
            "LIVE-PORTS",
            f"TCP Port Test: {tcp_host}:{tcp_port}",
            "ports",
            tcp_analysis,
            tcp_details,
        )
    )

    try:
        firewall_data = collect_firewall_profiles()
        firewall_analysis = analyze_firewall(firewall_data)
        firewall_details = firewall_data.get("raw_output")
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        firewall_analysis = make_inconclusive_report(
            f"Windows Firewall profile collection failed: {error}",
            "Run the scan on Windows and verify PowerShell access to firewall profile settings.",
        )
        firewall_details = str(error)

    results.append(
        make_live_result(
            "LIVE-FIREWALL",
            "Windows Firewall Profiles",
            "firewall",
            firewall_analysis,
            firewall_details,
        )
    )

    try:
        rule_data = collect_firewall_rules(tcp_host, tcp_port)
        rule_analysis = analyze_firewall_rules(rule_data)
        rule_details = rule_data.get("raw_output")
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        rule_analysis = make_inconclusive_report(
            f"Outbound firewall rule collection failed: {error}",
            "Run the scan on Windows and verify PowerShell access to active outbound firewall rules.",
        )
        rule_details = str(error)

    results.append(
        make_live_result(
            "LIVE-FIREWALL-RULES",
            f"Outbound Firewall Rules: {tcp_host}:{tcp_port}",
            "firewall_rules",
            rule_analysis,
            rule_details,
        )
    )

    default_routes = None
    if routing_data is not None:
        default_routes = [
            {
                "gateway": route.get("gateway"),
                "interface": route.get("interface"),
                "metric": route.get("metric"),
            }
            for route in routing_data.get("routes", [])
            if route.get("destination") == "0.0.0.0"
            and route.get("netmask") == "0.0.0.0"
        ]

    firewall_profiles = None
    if firewall_data is not None:
        firewall_profiles = {
            profile.get("name"): profile.get("enabled")
            for profile in firewall_data.get("profiles", [])
            if profile.get("name")
        }

    configuration_snapshot = {
        "adapter_name": adapter.get("name") if adapter else None,
        "ip_address": adapter.get("ip_address") if adapter else None,
        "subnet_mask": adapter.get("subnet_mask") if adapter else None,
        "default_gateway": gateway_ip,
        "dhcp_enabled": adapter.get("dhcp_enabled") if adapter else None,
        "dhcp_server": adapter.get("dhcp_server") if adapter else None,
        "dns_servers": sorted(adapter.get("dns_servers", [])) if adapter else None,
        "default_routes": default_routes,
        "firewall_profiles": firewall_profiles,
        "tcp_target": (
            {"host": tcp_data.get("host"), "port": tcp_data.get("port")}
            if tcp_data else None
        ),
        "tcp_result": tcp_data.get("result") if tcp_data else None,
    }

    return {
        "results": results,
        "correlation": correlate_findings(results),
        "configuration_snapshot": configuration_snapshot,
    }


def display_network_baseline() -> None:
    st.subheader("Network configuration baseline")
    st.caption(
        "Compare later scans with a configuration you have verified as known-good. "
        "A detected change is not automatically a fault."
    )

    try:
        baseline = load_baseline()
        history = load_scan_history()
    except (OSError, ValueError) as error:
        st.error(f"Could not load baseline or scan history: {error}")
        return

    history = sorted(
        history,
        key=lambda scan: scan.get("timestamp", ""),
        reverse=True,
    )
    eligible_scans = [
        scan for scan in history
        if isinstance(scan.get("configuration_snapshot"), dict)
        and scan["configuration_snapshot"]
    ]

    def scan_label(scan: dict) -> str:
        timestamp = scan.get("timestamp", "Unknown time").replace("T", " ")
        timestamp = timestamp.replace("+00:00", " UTC")
        status = status_label(scan.get("overall_status", "inconclusive"))
        return f"{timestamp} · {status}"

    if baseline:
        st.markdown("#### Saved baseline")
        st.write(f"Saved: {baseline.get('saved_at', 'Unknown time')}")
        st.write(
            f"Source scan: {baseline.get('source_scan_timestamp') or 'Not recorded'}"
        )
        st.caption(
            f"Source scan assessment: "
            f"{status_label(baseline.get('source_overall_status', 'unknown'))}"
        )
    else:
        st.info("No baseline has been saved. Run a live scan and select one as a known-good baseline.")

    if not eligible_scans:
        st.info(
            "No compatible scans are available yet. Run a new Live Network Scan; "
            "older history records do not contain configuration snapshots."
        )
    else:
        if baseline:
            st.markdown("#### Compare a saved scan against the baseline")
            current_scan = st.selectbox(
                "Current scan",
                eligible_scans,
                index=0,
                format_func=scan_label,
                key="baseline_compare_scan",
            )
            changes = compare_configuration(
                baseline["configuration_snapshot"],
                current_scan["configuration_snapshot"],
            )
            if changes:
                rows = [
                    {
                        "Field": change["label"],
                        "Baseline value": str(change["baseline_value"]),
                        "Current value": str(change["current_value"]),
                        "Assessment": change["assessment"],
                    }
                    for change in changes
                ]
                st.dataframe(rows, use_container_width=True, hide_index=True)
                st.caption(
                    "These are observed differences. Review context before treating any change as the cause of an issue."
                )
            else:
                st.success("No configuration differences were detected in the available fields.")

        st.divider()
        st.markdown("#### Save or replace the baseline")
        selected_scan = st.selectbox(
            "Select a scan to use as the baseline",
            eligible_scans,
            index=0,
            format_func=scan_label,
            key="baseline_source_scan",
        )
        confirm_baseline = st.checkbox(
            "I have verified that this scan represents a known-good network configuration.",
            key="confirm_network_baseline",
        )
        if st.button("Save selected scan as baseline", disabled=not confirm_baseline):
            try:
                save_baseline(selected_scan)
                st.success("Network baseline saved.")
                st.rerun()
            except (OSError, ValueError) as error:
                st.error(f"Could not save network baseline: {error}")

    if baseline:
        st.divider()
        st.markdown("#### Clear baseline")
        confirm_clear = st.checkbox(
            "I understand that clearing the baseline cannot be undone.",
            key="confirm_clear_baseline",
        )
        if st.button("Clear Network Baseline", disabled=not confirm_clear):
            try:
                clear_baseline()
                st.session_state.pop("confirm_clear_baseline", None)
                st.success("Network baseline cleared.")
                st.rerun()
            except OSError as error:
                st.error(f"Could not clear network baseline: {error}")


def display_diagnostic_report_downloads(scan: dict, filename_prefix: str) -> None:
    st.markdown("#### Export diagnostic report")
    st.caption(
        "The HTML report is suitable for review or printing. The JSON file preserves "
        "the complete scan record for structured analysis. Both may contain sensitive network details."
    )
    report_col1, report_col2 = st.columns(2)
    report_col1.download_button(
        "Download HTML diagnostic report",
        data=build_diagnostic_report_html(scan),
        file_name=f"{filename_prefix}.html",
        mime="text/html",
        key=f"{filename_prefix}_html_report",
    )
    report_col2.download_button(
        "Download JSON evidence",
        data=build_diagnostic_report_json(scan),
        file_name=f"{filename_prefix}.json",
        mime="application/json",
        key=f"{filename_prefix}_json_report",
    )


def display_scan_history() -> None:
    st.subheader("Saved live scans")
    st.caption("Scan records are stored locally in data/scan_history.json. They may contain private network and firewall information.")

    try:
        history = load_scan_history()
    except (OSError, ValueError) as error:
        st.error(f"Could not load scan history: {error}")
        return

    if not history:
        st.info("No saved scans yet. Run a Live Network Scan to create the first history record.")
    else:
        history = sorted(history, key=lambda scan: scan.get("timestamp", ""), reverse=True)
        st.metric("Saved scans", len(history))

        def scan_label(scan: dict) -> str:
            timestamp = scan.get("timestamp", "Unknown time").replace("T", " ")
            timestamp = timestamp.replace("+00:00", " UTC")
            return f"{timestamp} · {status_label(scan.get('overall_status', 'inconclusive'))}"

        selected_scan = st.selectbox(
            "Inspect a previous scan",
            history,
            format_func=scan_label,
        )

        st.markdown("#### Overall assessment")
        show_status_message(
            selected_scan.get("overall_status", "inconclusive"),
            selected_scan.get("overall_finding", "No overall finding was saved."),
        )
        display_correlation(selected_scan.get("correlation", {}))

        display_diagnostic_report_downloads(
            selected_scan,
            "diagnostic-" + selected_scan.get("scan_id", "report")[:8],
        )

        st.markdown("#### Individual diagnostic results")
        for result in selected_scan.get("results", []):
            analysis = result.get("analysis", {})
            result_status = analysis.get("status", "inconclusive")
            with st.expander(
                f"{result.get('title', 'Diagnostic')} · {status_label(result_status)}",
                expanded=False,
            ):
                display_analysis(result, live=True)

        if len(history) >= 2:
            st.divider()
            st.markdown("#### Compare two scans")
            older_index = min(1, len(history) - 1)
            compare_col1, compare_col2 = st.columns(2)
            older_scan = compare_col1.selectbox(
                "Earlier scan",
                history,
                index=older_index,
                format_func=scan_label,
                key="history_older_scan",
            )
            newer_scan = compare_col2.selectbox(
                "Later scan",
                history,
                index=0,
                format_func=scan_label,
                key="history_newer_scan",
            )

            if older_scan["scan_id"] == newer_scan["scan_id"]:
                st.warning("Select two different scans to compare.")
            else:
                comparison = compare_scans(older_scan, newer_scan)
                if comparison["overall_changed"]:
                    st.write(
                        f"Overall status: **{status_label(comparison['previous_overall_status'])}** → "
                        f"**{status_label(comparison['current_overall_status'])}**"
                    )
                else:
                    st.write(
                        f"Overall status unchanged: **{status_label(comparison['current_overall_status'])}**"
                    )

                if comparison["changes"]:
                    st.dataframe(
                        comparison["changes"],
                        use_container_width=True,
                        hide_index=True,
                    )
                else:
                    st.success("No diagnostic status changes were detected.")

        st.divider()
        st.markdown("#### Clear saved history")
        st.caption("This permanently deletes the local scan history file.")
        confirm_clear = st.checkbox(
            "I understand that clearing history cannot be undone.",
            key="confirm_clear_history",
        )
        if st.button("Clear Scan History", disabled=not confirm_clear):
            try:
                clear_scan_history()
                st.session_state.pop("confirm_clear_history", None)
                st.success("Scan history cleared.")
                st.rerun()
            except OSError as error:
                st.error(f"Could not clear scan history: {error}")


def display_incidents() -> None:
    st.subheader("Incident management")
    st.caption(
        "Document an issue from initial report through investigation, evidence collection, "
        "and verified resolution. Incident records are stored locally."
    )

    try:
        incidents = load_incidents()
        history = load_scan_history()
    except (OSError, ValueError) as error:
        st.error(f"Could not load incident or scan records: {error}")
        return

    st.markdown("#### Create an incident")
    with st.form("create_incident_form", clear_on_submit=True):
        incident_title = st.text_input("Incident title")
        incident_description = st.text_area("Description and reported impact")
        incident_severity = st.selectbox(
            "Severity",
            ["Low", "Medium", "High", "Critical"],
            index=1,
        )
        create_submitted = st.form_submit_button("Create incident")

    if create_submitted:
        try:
            create_incident(incident_title, incident_description, incident_severity)
            st.success("Incident created.")
            st.rerun()
        except (OSError, ValueError) as error:
            st.error(f"Could not create incident: {error}")

    if not incidents:
        st.info("No incidents have been created yet.")
        return

    incidents = sorted(
        incidents,
        key=lambda incident: incident.get("updated_at", ""),
        reverse=True,
    )

    def incident_label(incident: dict) -> str:
        return (
            f"{incident.get('title', 'Untitled')} · "
            f"{incident.get('status', 'Open')} · "
            f"{incident.get('severity', 'Medium')}"
        )

    selected_incident = st.selectbox(
        "Select an incident",
        incidents,
        format_func=incident_label,
    )
    st.divider()

    status_col, severity_col, created_col = st.columns(3)
    status_col.metric("Status", selected_incident.get("status", "Open"))
    severity_col.metric("Severity", selected_incident.get("severity", "Medium"))
    created_col.metric("Associated scans", len(selected_incident.get("associated_scans", [])))

    st.markdown("#### Reported issue")
    st.write(selected_incident.get("description") or "No description provided.")

    st.markdown("#### Update status or resolution")
    with st.form("update_incident_form"):
        status_options = ["Open", "Investigating", "Resolved"]
        current_status = selected_incident.get("status", "Open")
        status_index = status_options.index(current_status) if current_status in status_options else 0
        new_status = st.selectbox("Incident status", status_options, index=status_index)
        resolution = st.text_area(
            "Resolution summary",
            value=selected_incident.get("resolution", ""),
            help="Required when setting the incident to Resolved.",
        )
        update_submitted = st.form_submit_button("Save incident update")

    if update_submitted:
        try:
            update_incident(
                selected_incident["incident_id"],
                new_status,
                resolution,
            )
            st.success("Incident updated.")
            st.rerun()
        except (OSError, ValueError) as error:
            st.error(f"Could not update incident: {error}")

    st.markdown("#### Investigation timeline")
    for entry in reversed(selected_incident.get("timeline", [])):
        timestamp = entry.get("timestamp", "Unknown time").replace("T", " ")
        st.markdown(f"**{entry.get('entry_type', 'Update')}**")
        st.caption(timestamp)
        st.write(entry.get("note", ""))

    with st.form("add_incident_note_form", clear_on_submit=True):
        timeline_note = st.text_area("Add an investigation note")
        note_submitted = st.form_submit_button("Add timeline entry")

    if note_submitted:
        try:
            add_timeline_entry(selected_incident["incident_id"], timeline_note)
            st.success("Timeline entry added.")
            st.rerun()
        except (OSError, ValueError) as error:
            st.error(f"Could not add timeline entry: {error}")

    st.divider()
    st.markdown("#### Associate diagnostic evidence")
    associated_ids = {
        scan.get("scan_id")
        for scan in selected_incident.get("associated_scans", [])
    }
    available_scans = [
        scan for scan in history
        if scan.get("scan_id") not in associated_ids
    ]

    if available_scans:
        available_scans = sorted(
            available_scans,
            key=lambda scan: scan.get("timestamp", ""),
            reverse=True,
        )

        def scan_label(scan: dict) -> str:
            timestamp = scan.get("timestamp", "Unknown time").replace("T", " ")
            return (
                f"{timestamp} · "
                f"{status_label(scan.get('overall_status', 'inconclusive'))}"
            )

        selected_scan = st.selectbox(
            "Saved scan to attach",
            available_scans,
            format_func=scan_label,
        )
        if st.button("Attach scan to incident"):
            try:
                associate_scan(selected_incident["incident_id"], selected_scan)
                st.success("Scan evidence attached.")
                st.rerun()
            except (OSError, ValueError) as error:
                st.error(f"Could not attach scan: {error}")
    else:
        st.info("No unassociated saved scans are available.")

    associated_scans = selected_incident.get("associated_scans", [])
    if associated_scans:
        st.markdown("#### Attached scan evidence")
        for scan in associated_scans:
            with st.expander(
                f"{scan.get('timestamp', 'Unknown time')} · "
                f"{status_label(scan.get('overall_status', 'inconclusive'))}",
                expanded=False,
            ):
                st.write(scan.get("overall_finding", "No overall finding was saved."))
                st.json(scan.get("correlation", {}))
                for result in scan.get("results", []):
                    analysis = result.get("analysis", {})
                    st.markdown(
                        f"**{result.get('title', 'Diagnostic')}** — "
                        f"{status_label(analysis.get('status', 'inconclusive'))}"
                    )
                    st.write(analysis.get("finding", "No finding was recorded."))

    st.divider()
    st.markdown("#### Export incident report")
    report = build_incident_report_html(selected_incident)
    report_name = (
        "incident-"
        + selected_incident.get("incident_id", "report")[:8]
        + ".html"
    )
    st.download_button(
        "Download HTML incident report",
        data=report,
        file_name=report_name,
        mime="text/html",
    )



def display_troubleshooting_playbooks() -> None:
    st.subheader("Troubleshooting playbooks")
    st.caption(
        "Guided, read-only procedures for common network failures. "
        "Commands are displayed for review and are not executed by the application."
    )

    selected_name = st.selectbox(
        "Select a troubleshooting playbook",
        list_playbooks(),
    )
    playbook = get_playbook(selected_name)

    st.markdown("#### When to use this playbook")
    st.write(playbook["trigger"])
    st.markdown("#### Objective")
    st.write(playbook["purpose"])
    st.warning(playbook["safety"])

    st.markdown("#### Verification procedure")
    for index, step in enumerate(playbook["steps"], start=1):
        with st.expander(f"{index}. {step['title']}", expanded=index == 1):
            st.write(step["purpose"])
            st.code(step["command"], language="powershell")
            st.markdown("**Expected result**")
            st.write(step["expected"])
            st.markdown("**How to interpret the result**")
            st.write(step["interpretation"])

    st.markdown("#### Remediation guidance")
    for item in playbook["remediation"]:
        st.markdown(f"- {item}")

    st.markdown("#### Closure criteria")
    for item in playbook["closure"]:
        st.markdown(f"- [ ] {item}")


def display_correlation(correlation: dict) -> None:
    status = correlation.get("status", "inconclusive")
    st.subheader("Overall Root-Cause Assessment")
    show_status_message(status, f"{status_label(status)}: {correlation.get('finding', 'No overall finding was provided.')}")

    likely_causes = correlation.get("likely_causes", [])
    if likely_causes:
        st.markdown("#### Likely failure areas")
        for index, cause in enumerate(likely_causes, start=1):
            with st.container(border=True):
                st.markdown(f"**{index}. {cause.get('cause', 'Unspecified cause')}**")
                st.write(cause.get("reason", "No explanation was provided."))
                meta_col1, meta_col2 = st.columns(2)
                meta_col1.metric("Confidence", cause.get("confidence", "Unspecified"))
                score = cause.get("priority_score")
                if score is not None:
                    meta_col2.metric("Troubleshooting priority", f"{score}/100")
                    st.caption("Priority score helps order investigation; it is not a probability that this cause is correct.")
                else:
                    meta_col2.write("**Troubleshooting priority**")
                    meta_col2.write("Not scored")

                if cause.get("priority_explanation"):
                    st.caption(cause["priority_explanation"])

                supporting_evidence = cause.get("supporting_evidence", [])
                if supporting_evidence:
                    with st.expander("Supporting evidence", expanded=False):
                        for evidence in supporting_evidence:
                            st.markdown(f"- {evidence}")
                evidence_references = cause.get("evidence_references", [])
                if evidence_references:
                    with st.expander("Evidence source references", expanded=False):
                        st.json(evidence_references)
    else:
        st.info("No likely causes were identified from the available results.")

    st.markdown("#### Recommended next step")
    st.write(correlation.get("next_step", "Run additional diagnostics to gather more evidence."))

    with st.expander("All diagnostic findings", expanded=False):
        findings = correlation.get("supporting_findings", [])
        if findings:
            st.dataframe(findings, use_container_width=True, hide_index=True)
        else:
            st.write("No supporting findings were recorded.")

    conflicts = correlation.get("conflicts", [])
    if conflicts:
        with st.expander("Conflicting observations", expanded=False):
            st.warning("Some observations conflict. Repeat the affected tests before relying on the assessment.")
            st.json(conflicts)


def display_home() -> None:
    st.subheader("Network diagnostics workspace")
    st.caption("A practical workspace for network diagnostics, evidence collection, and troubleshooting.")
    st.write(
        "Investigate network configuration and connectivity issues, review diagnostic evidence, "
        "and document incidents from one place."
    )

    st.markdown("### Get started")
    live_col, scenario_col = st.columns(2)

    with live_col:
        with st.container(border=True):
            st.markdown("#### Live Network Scan")
            st.write("Run read-only checks against this computer's network configuration and connectivity.")
            st.button(
                "Open Live Network Scan",
                type="primary",
                use_container_width=True,
                on_click=navigate_to,
                args=("Live Network Scan",),
            )

    with scenario_col:
        with st.container(border=True):
            st.markdown("#### Example Scenarios")
            st.write("Explore simulated network failures and see how the analysis identifies possible causes.")
            st.button(
                "Explore Example Scenarios",
                use_container_width=True,
                on_click=navigate_to,
                args=("Example Scenarios",),
            )

    st.markdown("### Other tools")
    history_col, baseline_col, incident_col, playbook_col = st.columns(4)

    with history_col:
        st.markdown("**Scan History**")
        st.caption("Review and compare previous scans.")
        st.button("Open history", use_container_width=True, on_click=navigate_to, args=("Scan History",))

    with baseline_col:
        st.markdown("**Network Baseline**")
        st.caption("Identify changes from a known-good configuration.")
        st.button("Open baseline", use_container_width=True, on_click=navigate_to, args=("Network Baseline",))

    with incident_col:
        st.markdown("**Incident Management**")
        st.caption("Track investigations and attach diagnostic evidence.")
        st.button("Open incidents", use_container_width=True, on_click=navigate_to, args=("Incident Management",))

    with playbook_col:
        st.markdown("**Troubleshooting Playbooks**")
        st.caption("Follow structured procedures for common failures.")
        st.button("Open playbooks", use_container_width=True, on_click=navigate_to, args=("Troubleshooting Playbooks",))

    st.divider()
    st.caption("Ready. No diagnostic checks have been executed.")


def navigate_to(page: str) -> None:
    st.session_state["mode"] = page


st.set_page_config(
    page_title="Network Failure Analysis Lab",
    page_icon=":material/network_check:",
    layout="wide",
)

if "mode" not in st.session_state:
    st.session_state["mode"] = "Home"

st.title("Network Failure Analysis Lab")
st.caption("Developed by Jacob Supplee")

mode = st.sidebar.radio(
    "Navigation",
    [
        "Home",
        "Live Network Scan",
        "Example Scenarios",
        "Scan History",
        "Network Baseline",
        "Incident Management",
        "Troubleshooting Playbooks",
    ],
    key="mode",
)

if mode == "Home":
    display_home()

elif mode == "Live Network Scan":
    st.subheader("Live network checks")
    st.caption("Runs local configuration, DNS, connectivity, routing, and TCP checks on this computer.")

    input_col1, input_col2 = st.columns([3, 1])
    tcp_host = input_col1.text_input("Target hostname or IP address", value="example.com")
    tcp_port = input_col2.number_input(
        "Target TCP port",
        min_value=1,
        max_value=65535,
        value=443,
        step=1,
    )

    if st.button("Run Live Network Scan", type="primary"):
        if not tcp_host.strip():
            st.error("Enter a target hostname or IP address.")
        else:
            try:
                with st.spinner("Collecting network evidence and analyzing results..."):
                    scan = run_live_scan(tcp_host.strip(), int(tcp_port))
                save_scan(scan)
                st.success("Live scan completed and saved to Scan History.")
                saved_scan = load_scan_history()[-1]

                results = scan["results"]
                correlation = scan["correlation"]

                investigation_count = sum(
                    result["analysis"].get("status") == "investigate"
                    for result in results
                )
                inconclusive_count = sum(
                    result["analysis"].get("status") == "inconclusive"
                    for result in results
                )

                metric_col1, metric_col2, metric_col3 = st.columns(3)
                metric_col1.metric("Checks completed", len(results))
                metric_col2.metric("Need investigation", investigation_count)
                metric_col3.metric("Inconclusive", inconclusive_count)

                st.divider()
                display_correlation(correlation)

                st.divider()
                st.subheader("Individual diagnostic results")
                st.caption("Open a result for its evidence, recommended tests, and verification steps.")

                for result in results:
                    analysis = result["analysis"]
                    result_status = analysis.get("status", "inconclusive")
                    with st.expander(
                        f"{result['title']} · {status_label(result_status)}",
                        expanded=False,
                    ):
                        display_analysis(result, live=True)

                st.divider()
                display_diagnostic_report_downloads(
                    saved_scan,
                    "diagnostic-" + saved_scan.get("scan_id", "report")[:8],
                )

            except (OSError, RuntimeError, ValueError, KeyError) as error:
                st.error(f"The live scan could not complete: {error}")

elif mode == "Example Scenarios":
    st.subheader("Example scenario analysis")
    st.caption(
        "Select a simulated network condition and run its analysis. "
        "These scenarios use sample evidence and do not inspect your live network."
    )
    selected_scenario = st.selectbox("Select an example scenario", list(SCENARIOS))
    if st.button("Run Example Scenario", type="primary"):
        try:
            result = run_analysis(SCENARIOS[selected_scenario])
            display_analysis(result)
        except (OSError, RuntimeError, ValueError, KeyError) as error:
            st.error(f"Scenario analysis could not run: {error}")

elif mode == "Scan History":
    display_scan_history()

elif mode == "Network Baseline":
    display_network_baseline()

elif mode == "Incident Management":
    display_incidents()

elif mode == "Troubleshooting Playbooks":
    display_troubleshooting_playbooks()
