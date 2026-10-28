from pathlib import Path

import streamlit as st

from src.analysis_runner import run_analysis
from src.analyzers.connectivity import analyze_connectivity
from src.analyzers.dhcp import analyze_dhcp
from src.analyzers.dns import analyze_dns
from src.correlation import correlate_findings
from src.diagnostics import build_report
from src.evidence_collection import (
    collect_connectivity,
    collect_dns_resolution,
    collect_network_configuration,
)

SCENARIOS = {
    "DHCP diagnostic": Path("scenarios/apipa_dhcp.json"),
    "DNS diagnostic": Path("scenarios/dns_failure.json"),
}

def display_analysis(result: dict, live: bool = False) -> None:
    analysis = result["analysis"]

    st.subheader(result.get("title", "Diagnostic result"))
    st.write(f"**Status:** {analysis['status']}")
    st.write(f"**Finding:** {analysis['finding']}")
    st.write(f"**Severity:** {analysis.get('severity', 'Not specified')}")
    st.write(f"**Recommended next step:** {analysis['next_step']}")

    with st.expander("Evidence", expanded=True):
        if analysis["evidence"]:
            st.json(analysis["evidence"])
        else:
            st.write("No evidence was recorded.")

    with st.expander("Possible causes"):
        if analysis["hypotheses"]:
            st.json(analysis["hypotheses"])
        else:
            st.write("No possible causes were identified.")

    with st.expander("Recommended tests"):
        if analysis["next_tests"]:
            st.json(analysis["next_tests"])
        else:
            st.write("No additional tests were recommended.")

    with st.expander("Verification steps"):
        if analysis["verification"]:
            for step in analysis["verification"]:
                st.write(f"- {step}")
        else:
            st.write("No verification steps were recorded.")

    if result.get("details"):
        with st.expander("Collection details"):
            st.write(result["details"])

    if not live and "expected_status" in result:
        matches = result["matches_expected"]
        st.write(
            f"**Scenario expectation:** "
            f"{'Matched' if matches else 'Did not match'}"
        )

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

def run_live_scan() -> dict:
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

    return {
        "results": results,
        "correlation": correlate_findings(results),
    }

def display_correlation(correlation: dict) -> None:
    st.subheader("Overall Root-Cause Assessment")
    st.write(f"**Status:** {correlation['status']}")
    st.write(f"**Finding:** {correlation['finding']}")

    st.write("**Likely failure areas**")
    if correlation["likely_causes"]:
        for cause in correlation["likely_causes"]:
            st.markdown(f"**{cause['cause']}**")
            st.write(f"Reason: {cause['reason']}")
            st.write(f"Confidence: {cause['confidence']}")
    else:
        st.write("No likely causes were identified from the supplied results.")

    st.write(f"**Recommended next step:** {correlation['next_step']}")

    with st.expander("Supporting diagnostic findings"):
        st.json(correlation["supporting_findings"])


st.set_page_config(
    page_title="Network Failure Analysis Lab",
    page_icon=":material/network_check:",
    layout="wide",
)

st.title("Network Failure Analysis Lab")
st.write(
    "An evidence-driven tool for investigating network configuration, "
    "DNS resolution, and connectivity problems."
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
    if st.button("Run Live Network Scan", type="primary"):
        try:
            scan = run_live_scan()
            results = scan["results"]
            correlation = scan["correlation"]

            investigation_count = sum(
                result["analysis"]["status"] == "investigate"
                for result in results
            )
            inconclusive_count = sum(
                result["analysis"]["status"] == "inconclusive"
                for result in results
            )

            col1, col2, col3 = st.columns(3)
            col1.metric("Checks Run", len(results))
            col2.metric("Need Investigation", investigation_count)
            col3.metric("Inconclusive", inconclusive_count)

            display_correlation(correlation)

            st.divider()
            st.subheader("Individual Diagnostic Reports")

            for result in results:
                with st.expander(result["title"]):
                    display_analysis(result, live=True)

        except (OSError, RuntimeError, ValueError, KeyError) as error:
            st.error(f"The live scan could not complete: {error}")

elif mode == "Combined scan":
    st.subheader("Scenario Analysis")

    for scenario_name, scenario_path in SCENARIOS.items():
        st.markdown(f"### {scenario_name}")

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
