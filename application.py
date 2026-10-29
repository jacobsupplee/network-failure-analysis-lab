from pathlib import Path

import streamlit as st

from src.analyzers.connectivity import analyze_connectivity
from src.analyzers.dhcp import analyze_dhcp
from src.analyzers.firewall import analyze_firewall
from src.analyzers.dns import analyze_dns
from src.analyzers.ports import analyze_port
from src.analyzers.routing import analyze_routing
from src.analysis_runner import run_analysis
from src.correlation import correlate_findings
from src.diagnostics import build_report
from src.evidence_collection import (
    collect_connectivity,
    collect_dns_resolution,
    collect_firewall_profiles,
    collect_network_configuration,
    collect_routing_table,
    collect_tcp_connection,
)

SCENARIOS = {
    "DHCP diagnostic": Path("scenarios/apipa_dhcp.json"),
    "DNS diagnostic": Path("scenarios/dns_failure.json"),
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

    return {
        "results": results,
        "correlation": correlate_findings(results),
    }


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


st.set_page_config(
    page_title="Network Failure Analysis Lab",
    page_icon=":material/network_check:",
    layout="wide",
)

st.title("Network Failure Analysis Lab")
st.write(
    "An evidence-driven tool for investigating network configuration, "
    "DNS resolution, connectivity, routing, and TCP port problems."
)

mode = st.selectbox(
    "Select diagnostic mode",
    [
        "DHCP diagnostic",
        "DNS diagnostic",
        "Combined scan",
        "Live Network Scan",
    ],
)

if mode == "Live Network Scan":
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

            except (OSError, RuntimeError, ValueError, KeyError) as error:
                st.error(f"The live scan could not complete: {error}")

elif mode == "Combined scan":
    st.subheader("Scenario analysis")
    st.caption("Run the bundled example scenarios to see how the tool handles known network problems.")

    for scenario_name, scenario_path in SCENARIOS.items():
        with st.expander(scenario_name, expanded=True):
            try:
                result = run_analysis(scenario_path)
                display_analysis(result)
            except (OSError, RuntimeError, ValueError, KeyError) as error:
                st.error(f"Could not run {scenario_name}: {error}")

elif mode in SCENARIOS:
    try:
        result = run_analysis(SCENARIOS[mode])
        display_analysis(result)
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        st.error(f"Diagnostic could not run: {error}")
