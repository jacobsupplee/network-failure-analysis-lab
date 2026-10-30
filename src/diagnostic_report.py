import html
import json
from datetime import datetime, timezone


def _display_value(value) -> str:
    if value is None:
        return "Not recorded"
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, ensure_ascii=False)
    if isinstance(value, bool):
        return "Enabled" if value else "Disabled"
    return str(value)


def _table_rows(items: list[dict], columns: list[tuple[str, str]]) -> str:
    rows = []
    for item in items:
        cells = "".join(
            f"<td>{html.escape(_display_value(item.get(key)))}</td>"
            for key, _ in columns
        )
        rows.append(f"<tr>{cells}</tr>")
    if not rows:
        return f'<tr><td colspan="{len(columns)}">No data recorded.</td></tr>'
    return "".join(rows)


def build_diagnostic_report_html(scan: dict) -> str:
    """Build a self-contained HTML report from a saved or live scan record."""
    if not isinstance(scan, dict) or not isinstance(scan.get("results"), list):
        raise ValueError("A diagnostic scan with a results list is required.")

    correlation = scan.get("correlation", {})
    results = scan.get("results", [])
    escape = html.escape
    status = escape(str(scan.get("overall_status", correlation.get("status", "inconclusive"))))
    finding = escape(str(scan.get("overall_finding", correlation.get("finding", "No overall finding was recorded."))))
    timestamp = escape(str(scan.get("timestamp", "Not recorded")))
    scan_id = escape(str(scan.get("scan_id", "Unsaved scan")))
    next_step = escape(str(correlation.get("next_step", "No next step was recorded.")))

    result_rows = []
    for result in results:
        analysis = result.get("analysis", {})
        result_rows.append(
            "<tr>"
            f"<td>{escape(str(result.get('title', 'Diagnostic')))}</td>"
            f"<td>{escape(str(analysis.get('status', 'inconclusive')))}</td>"
            f"<td>{escape(str(analysis.get('severity', 'Not specified')))}</td>"
            f"<td>{escape(str(analysis.get('finding', 'No finding recorded.')))}</td>"
            "</tr>"
        )
    if not result_rows:
        result_rows.append('<tr><td colspan="4">No diagnostic results recorded.</td></tr>')

    cause_sections = []
    for index, cause in enumerate(correlation.get("likely_causes", []), start=1):
        evidence = "".join(
            f"<li>{escape(str(item))}</li>"
            for item in cause.get("supporting_evidence", [])
        ) or "<li>No supporting evidence recorded.</li>"
        references = cause.get("evidence_references", [])
        cause_sections.append(
            f"<article><h3>{index}. {escape(str(cause.get('cause', 'Possible cause')))}</h3>"
            f"<p>{escape(str(cause.get('reason', '')))}</p>"
            f"<p><strong>Confidence:</strong> {escape(str(cause.get('confidence', 'Not specified')))}"
            f" &nbsp; <strong>Priority:</strong> {escape(str(cause.get('priority_score', 'Not scored')))}"
            f"</p><ul>{evidence}</ul>"
            f"<details><summary>Evidence source references</summary><pre>{escape(_display_value(references))}</pre></details></article>"
        )
    if not cause_sections:
        cause_sections.append("<p>No likely causes were identified from the available evidence.</p>")

    diagnostic_sections = []
    for result in results:
        analysis = result.get("analysis", {})
        title = escape(str(result.get("title", "Diagnostic")))
        evidence = escape(_display_value(analysis.get("evidence", [])))
        hypotheses = escape(_display_value(analysis.get("hypotheses", [])))
        next_tests = escape(_display_value(analysis.get("next_tests", [])))
        verification = escape(_display_value(analysis.get("verification", [])))
        details = escape(str(result.get("details", "No raw collection output recorded.")))
        diagnostic_sections.append(
            f"<article><h3>{title}</h3>"
            f"<p><strong>Status:</strong> {escape(str(analysis.get('status', 'inconclusive')))}"
            f" &nbsp; <strong>Severity:</strong> {escape(str(analysis.get('severity', 'Not specified')))}</p>"
            f"<p>{escape(str(analysis.get('finding', 'No finding recorded.')))}</p>"
            f"<details><summary>Evidence</summary><pre>{evidence}</pre></details>"
            f"<details><summary>Analyzer hypotheses</summary><pre>{hypotheses}</pre></details>"
            f"<details><summary>Recommended tests</summary><pre>{next_tests}</pre></details>"
            f"<details><summary>Verification checklist</summary><pre>{verification}</pre></details>"
            f"<details><summary>Raw collection output</summary><pre>{details}</pre></details></article>"
        )

    configuration = scan.get("configuration_snapshot", {})
    config_rows = "".join(
        f"<tr><th>{escape(str(key.replace('_', ' ').title()))}</th><td><pre>{escape(_display_value(value))}</pre></td></tr>"
        for key, value in configuration.items()
    ) or '<tr><td colspan="2">No configuration snapshot recorded.</td></tr>'

    supporting_findings = correlation.get("supporting_findings", [])
    supporting_rows = _table_rows(
        supporting_findings,
        [("diagnostic", "Diagnostic"), ("status", "Status"), ("finding", "Finding")],
    )
    conflicts = correlation.get("conflicts", [])
    conflict_content = escape(_display_value(conflicts)) if conflicts else "No conflicting observations were recorded."

    generated_at = datetime.now(timezone.utc).isoformat()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Diagnostic Report</title>
<style>
body {{ font-family: Arial, sans-serif; color: #202124; line-height: 1.55; max-width: 1150px; margin: 36px auto; padding: 0 24px; }}
h1, h2, h3 {{ color: #1f2937; }}
.meta {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; background: #f3f4f6; padding: 16px; border-radius: 8px; }}
.meta strong {{ display: block; font-size: 12px; text-transform: uppercase; color: #555; }}
section {{ margin-top: 30px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ text-align: left; vertical-align: top; padding: 10px; border-bottom: 1px solid #ddd; overflow-wrap: anywhere; }}
th {{ background: #f3f4f6; }}
article {{ border: 1px solid #ddd; border-radius: 8px; padding: 14px 18px; margin: 14px 0; break-inside: avoid; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #f8f9fa; padding: 12px; border-radius: 5px; }}
summary {{ cursor: pointer; font-weight: 600; margin: 8px 0; }}
.note {{ color: #555; font-size: 13px; }}
@media print {{ body {{ margin: 12mm; }} article {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<h1>Network Diagnostic Report</h1>
<p class="note">Generated {escape(generated_at)} · Evidence-based assessment; findings do not independently prove root cause.</p>
<div class="meta">
<div><strong>Overall status</strong>{status}</div>
<div><strong>Scan timestamp</strong>{timestamp}</div>
<div><strong>Scan ID</strong>{scan_id}</div>
</div>
<section><h2>Executive summary</h2><p>{finding}</p><p><strong>Recommended next step:</strong> {next_step}</p></section>
<section><h2>Diagnostic results</h2><table><thead><tr><th>Check</th><th>Status</th><th>Severity</th><th>Finding</th></tr></thead><tbody>{''.join(result_rows)}</tbody></table></section>
<section><h2>Likely failure areas</h2>{''.join(cause_sections)}</section>
<section><h2>Supporting findings</h2><table><thead><tr><th>Diagnostic</th><th>Status</th><th>Finding</th></tr></thead><tbody>{supporting_rows}</tbody></table></section>
<section><h2>Conflicting observations</h2><pre>{conflict_content}</pre></section>
<section><h2>Configuration snapshot</h2><table><tbody>{config_rows}</tbody></table></section>
<section><h2>Diagnostic evidence and next actions</h2>{''.join(diagnostic_sections)}</section>
<footer class="note">Network Failure Analysis Lab · Report contains local network configuration and diagnostic evidence. Review before sharing.</footer>
</body>
</html>"""


def build_diagnostic_report_json(scan: dict) -> str:
    """Return the complete scan record as formatted JSON evidence."""
    if not isinstance(scan, dict) or not isinstance(scan.get("results"), list):
        raise ValueError("A diagnostic scan with a results list is required.")
    return json.dumps(scan, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
