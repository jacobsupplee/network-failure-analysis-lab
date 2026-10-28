
from pathlib import Path

import streamlit as st

from src.analysis_runner import run_analysis
from src.analyzers.connectivity import analyze_connectivity
from src.analyzers.dhcp import analyze_dhcp
from src.analyzers.dns import analyze_dns
from src.diagnostics import build_report
from src.evidence_collection import (
    collect_connectivity,
    collect_dns_resolution,
    collect_network_configuration,
)

SCENARIOS_DIR = Path(__file__).parent / "scenarios"
SCENARIOS = {
    "DHCP diagnostic": SCENARIOS_DIR / "apipa_dhcp.json",
    "DNS diagnostic": SCENARIOS_DIR / "dns_failure.json",
}


def display_analysis(result: dict, live: bool = False) -> None:
    analysis = result["analysis"]

    st.markdown(f"### {result['title']}")

    if live:
        col1, col2 = st.columns(2)

        with col1:
            st.metric("Diagnostic ID", result["scenario_id"])

        with col2:
            st.metric("Diagnostic status", analysis["status"].upper())
    else:
        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Scenario ID", result["scenario_id"])

        with col2:
            st.metric("Diagnostic status", analysis["status"].upper())

        with col3:
            outcome = "Match" if result["matches_expected"] else "Mismatch"
            st.metric("Expected outcome", outcome)

    st.markdown("#### Finding")
    st.write(analysis["finding"])

    st.markdown("#### Observed evidence")
    st.dataframe(
        analysis["evidence"],
        hide_index=True,
        use_container_width=True,
    )

    if live:
        st.caption(
            "Evidence was collected from the current Windows system. "
            "Results describe the checks performed and do not guarantee "
            "that all network services are functioning."
        )
    else:
        st.caption(
            "Evidence is supplied by the selected scenario and has not "
            "been collected from the live network."
        )

    st.markdown("#### Possible causes")

    if analysis["hypotheses"]:
        for hypothesis in analysis["hypotheses"]:
            with st.container(border=True):
                st.markdown(f"**{hypothesis['cause']}**")
                st.write(hypothesis["reason"])
                st.caption(f"Assessment: {hypothesis['confidence']}")
    else:
        st.write("No additional hypotheses were generated.")

    st.markdown("#### Recommended next tests")

    for index, test in enumerate(analysis["next_tests"], start=1):
        with st.container(border=True):
            st.markdown(f"**{index}. {test['test']}**")
            st.write(test["purpose"])

    st.markdown("#### Verification checklist")

    for index, item in enumerate(analysis["verification"]):
        st.checkbox(
            item,
            key=f"verify_{result['scenario_id']}_{index}",
        )

    st.info(f"Recommended first step: {analysis['next_step']}")

    if not live:
        if result["matches_expected"]:
            st.success("The result matches the expected scenario outcome.")
        else:
            st.warning("The result differs from the expected scenario outcome.")


def run_live_scan() -> list[dict]:
    results = []
    adapter = None
    gateway_ip = None

    try:
        config = collect_network_configuration()
        adapter = config["primary_adapter"]
        gateway_ip = adapter["default_gateway"] if adapter else None

        dhcp_evidence = {
            "ip_address": adapter["ip_address"] if adapter else None,
            "default_gateway": gateway_ip,
            "dhcp_server": adapter["dhcp_server"] if adapter else None,
        }

        dhcp_analysis = analyze_dhcp(dhcp_evidence)
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        dhcp_analysis = build_report(
            status="inconclusive",
            finding=f"Network configuration could not be collected: {error}",
            next_step="Verify that Windows network configuration can be queried, then retry.",
            evidence=[],
            hypotheses=[],
            next_tests=[
                {
                    "test": "Run ipconfig /all",
                    "purpose": "Inspect the system's network configuration.",
                }
            ],
            verification=[
                "Confirm that network configuration was collected successfully."
            ],
        )

    results.append({
        "scenario_id": "LIVE-DHCP",
        "title": "Live Windows network configuration",
        "analysis": dhcp_analysis,
    })

    try:
        dns_result = collect_dns_resolution()
        dns_servers = adapter["dns_servers"] if adapter else []
        dns_evidence = {
            "hostname": dns_result["hostname"],
            "dns_server": dns_servers[0] if dns_servers else None,
            "resolution_result": dns_result["resolution_result"],
        }
        dns_analysis = analyze_dns(dns_evidence)
        dns_details = dns_result["details"]
        dns_title = f"Live DNS resolution: {dns_result['hostname']}"
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        dns_analysis = build_report(
            status="inconclusive",
            finding=f"DNS evidence could not be collected: {error}",
            next_step="Verify that the DNS lookup can run, then retry.",
            evidence=[],
            hypotheses=[],
            next_tests=[
                {
                    "test": "Run nslookup example.com",
                    "purpose": "Check whether hostname resolution can be tested.",
                }
            ],
            verification=[
                "Confirm the DNS lookup completed and its result was recorded."
            ],
        )
        dns_details = str(error)
        dns_title = "Live DNS resolution"

    results.append({
        "scenario_id": "LIVE-DNS",
        "title": dns_title,
        "analysis": dns_analysis,
        "dns_details": dns_details,
    })

    try:
        connectivity_evidence = collect_connectivity(gateway_ip)
        connectivity_analysis = analyze_connectivity(connectivity_evidence)
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        connectivity_analysis = build_report(
            status="inconclusive",
            finding=f"Connectivity evidence could not be collected: {error}",
            next_step="Verify that connectivity checks can run, then retry.",
            evidence=[],
            hypotheses=[],
            next_tests=[
                {
                    "test": "Test gateway and external reachability",
                    "purpose": "Collect connectivity evidence.",
                }
            ],
            verification=[
                "Confirm that connectivity results were collected successfully."
            ],
        )

    results.append({
        "scenario_id": "LIVE-CONNECTIVITY",
        "title": "Live connectivity and routing checks",
        "analysis": connectivity_analysis,
    })

    return results


st.set_page_config(
    page_title="Network Failure Analysis Lab",
    page_icon="🖧",
    layout="wide",
)

st.title("Network Failure Analysis Lab")
st.caption("Evidence-driven network troubleshooting")

st.write(
    "Run individual diagnostics, analyze sample scenarios, "
    "or collect evidence from the current Windows system."
)

st.divider()

scan_mode = st.selectbox(
    "Select diagnostic mode",
    [
        "DHCP diagnostic",
        "DNS diagnostic",
        "Combined scan",
        "Live Network Scan",
    ],
)

if scan_mode == "Combined scan":
    st.write(
        "Runs both analyzers against their predefined scenario evidence."
    )
elif scan_mode == "Live Network Scan":
    st.write(
        "Collects Windows network configuration, tests DNS resolution, "
        "and checks gateway and external IP reachability. "
        "These are read-only diagnostic checks."
    )
else:
    st.write(f"Selected diagnostic: **{scan_mode}**")

if st.button("Run diagnostic", type="primary"):
    try:
        st.divider()
        st.subheader("Diagnostic report")

        if scan_mode == "Live Network Scan":
            with st.spinner("Collecting live network evidence..."):
                results = run_live_scan()

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Checks run", len(results))

            with col2:
                st.metric(
                    "Need investigation",
                    sum(
                        result["analysis"]["status"] == "investigate"
                        for result in results
                    ),
                )

            with col3:
                st.metric(
                    "Inconclusive",
                    sum(
                        result["analysis"]["status"] == "inconclusive"
                        for result in results
                    ),
                )

            for result in results:
                with st.expander(
                    f"{result['scenario_id']} — {result['title']}",
                    expanded=True,
                ):
                    display_analysis(result, live=True)

                    if result["scenario_id"] == "LIVE-DNS":
                        with st.expander("DNS lookup details"):
                            st.code(
                                result["dns_details"] or "No output returned."
                            )
        else:
            selected_scenarios = (
                list(SCENARIOS.values())
                if scan_mode == "Combined scan"
                else [SCENARIOS[scan_mode]]
            )

            results = [
                run_analysis(path) for path in selected_scenarios
            ]

            if scan_mode == "Combined scan":
                investigate_count = sum(
                    result["analysis"]["status"] == "investigate"
                    for result in results
                )
                inconclusive_count = sum(
                    result["analysis"]["status"] == "inconclusive"
                    for result in results
                )

                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric("Checks run", len(results))

                with col2:
                    st.metric("Need investigation", investigate_count)

                with col3:
                    st.metric("Inconclusive", inconclusive_count)

            for result in results:
                if scan_mode == "Combined scan":
                    with st.expander(
                        f"{result['scenario_id']} — {result['title']}",
                        expanded=True,
                    ):
                        display_analysis(result)
                else:
                    display_analysis(result)

    except (OSError, RuntimeError, ValueError, KeyError) as error:
        st.error(f"Unable to run the diagnostic: {error}")
