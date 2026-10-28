def build_report(
    status: str,
    finding: str,
    next_step: str,
    evidence: list[dict],
    hypotheses: list[dict],
    next_tests: list[dict],
    verification: list[str],
) -> dict:
    """Build a consistent report for any diagnostic analyzer."""

    severity_by_status = {
        "investigate": "Needs investigation",
        "inconclusive": "Insufficient data",
    }

    return {
        "status": status,
        "finding": finding,
        "next_step": next_step,
        "severity": severity_by_status.get(status, "Informational"),
        "evidence": evidence,
        "hypotheses": hypotheses,
        "next_tests": next_tests,
        "verification": verification,
    }
