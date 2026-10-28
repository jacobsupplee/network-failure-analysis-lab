from pathlib import Path

import streamlit as st

from src.analysis_runner import run_analysis

SCENARIO_PATH = (
    Path(__file__).parent
    / "scenarios"
    / "apipa_dhcp.json"
)

st.set_page_config(
    page_title="Network Failure Analysis Lab",
    page_icon="🖧",
    layout="wide",
)

st.title("Network Failure Analysis Lab")
st.caption("Evidence-driven network troubleshooting")

st.write(
    "Review observed network evidence, evaluate possible causes, "
    "and identify the next diagnostic steps."
)

st.divider()

st.subheader("DHCP troubleshooting")
st.write("**Scenario:** Workstation receives an APIPA address")

if st.button("Run diagnostic", type="primary"):
    try:
        result = run_analysis(SCENARIO_PATH)
        analysis = result["analysis"]

        st.divider()
        st.subheader("Diagnostic report")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Scenario ID", result["scenario_id"])

        with col2:
            st.metric("Diagnostic status", analysis["status"].upper())

        with col3:
            outcome = (
                "Match"
                if result["matches_expected"]
                else "Mismatch"
            )
            st.metric("Expected outcome", outcome)

        st.markdown("### Finding")
        st.write(analysis["finding"])

        st.markdown("### Observed evidence")
        st.dataframe(
            analysis["evidence"],
            hide_index=True,
            use_container_width=True,
        )

        st.caption(
            "Evidence reflects the values supplied by the scenario. "
            "Missing information has not been independently verified."
        )

        st.markdown("### Possible causes")
        for hypothesis in analysis["hypotheses"]:
            with st.container(border=True):
                st.markdown(f"**{hypothesis['cause']}**")
                st.write(hypothesis["reason"])
                st.caption(
                    f"Assessment: {hypothesis['confidence']}"
                )

        st.markdown("### Recommended next tests")
        for index, test in enumerate(analysis["next_tests"], start=1):
            with st.container(border=True):
                st.markdown(f"**{index}. {test['test']}**")
                st.write(test["purpose"])

        st.markdown("### Verification checklist")
        for item in analysis["verification"]:
            st.checkbox(item, key=f"verify_{result['scenario_id']}_{item}")

        st.info(
            f"Recommended first step: {analysis['next_step']}"
        )

        if result["matches_expected"]:
            st.success("The diagnostic result matches the expected scenario outcome.")
        else:
            st.warning("The diagnostic result differs from the expected scenario outcome.")

    except (OSError, ValueError, KeyError) as error:
        st.error(f"Unable to analyze the scenario: {error}")
