
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
    layout="centered",
)

st.title("Network Failure Analysis Lab")
st.write(
    "Investigate network issues using observed evidence "
    "and repeatable diagnostic scenarios."
)

st.subheader("DHCP troubleshooting")

if st.button("Analyze APIPA scenario"):
    try:
        result = run_analysis(SCENARIO_PATH)
        analysis = result["analysis"]

        st.write(f"**Scenario:** {result['title']}")
        st.write(f"**Finding:** {analysis['finding']}")
        st.write(f"**Recommended next step:** {analysis['next_step']}")

        if analysis["status"] == "investigate":
            st.warning("Further investigation is needed.")
        else:
            st.info(f"Diagnostic status: {analysis['status']}")

        if result["matches_expected"]:
            st.success("Result matches the expected scenario outcome.")
        else:
            st.error("Result differs from the expected scenario outcome.")

    except (OSError, ValueError, KeyError) as error:
        st.error(f"Unable to analyze the scenario: {error}")
