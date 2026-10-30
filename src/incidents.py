import html
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

INCIDENT_PATH = Path("data/incidents.json")
INCIDENT_STATUSES = {"Open", "Investigating", "Resolved"}
INCIDENT_SEVERITIES = {"Low", "Medium", "High", "Critical"}


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_incidents(incidents: list[dict], incident_path: Path) -> None:
    incident_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = incident_path.with_suffix(incident_path.suffix + ".tmp")

    try:
        with temporary_path.open("w", encoding="utf-8") as incident_file:
            json.dump(incidents, incident_file, indent=2, ensure_ascii=False)
            incident_file.write("\n")
        temporary_path.replace(incident_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def load_incidents(incident_path: Path = INCIDENT_PATH) -> list[dict]:
    """Load locally saved incident records."""
    if not incident_path.exists():
        return []

    try:
        with incident_path.open("r", encoding="utf-8") as incident_file:
            incidents = json.load(incident_file)
    except json.JSONDecodeError as error:
        raise ValueError("Incident records contain invalid JSON.") from error

    if not isinstance(incidents, list):
        raise ValueError("Incident records must contain a JSON list.")

    return incidents


def create_incident(
    title: str,
    description: str,
    severity: str = "Medium",
    incident_path: Path = INCIDENT_PATH,
) -> dict:
    """Create an incident and its initial timeline entry."""
    title = title.strip()
    description = description.strip()

    if not title:
        raise ValueError("Incident title cannot be empty.")
    if severity not in INCIDENT_SEVERITIES:
        raise ValueError("Incident severity is not supported.")

    incident = {
        "incident_id": str(uuid4()),
        "title": title,
        "description": description,
        "severity": severity,
        "status": "Open",
        "created_at": _timestamp(),
        "updated_at": _timestamp(),
        "resolution": "",
        "associated_scans": [],
        "timeline": [{
            "timestamp": _timestamp(),
            "entry_type": "Incident created",
            "note": description or "Incident record created.",
        }],
    }

    incidents = load_incidents(incident_path)
    incidents.append(incident)
    _write_incidents(incidents, incident_path)
    return incident


def _find_incident(incidents: list[dict], incident_id: str) -> dict:
    for incident in incidents:
        if incident.get("incident_id") == incident_id:
            return incident
    raise ValueError("Incident was not found.")


def add_timeline_entry(
    incident_id: str,
    note: str,
    entry_type: str = "Investigation note",
    incident_path: Path = INCIDENT_PATH,
) -> dict:
    """Append a timestamped investigation note to an incident."""
    note = note.strip()
    if not note:
        raise ValueError("Timeline note cannot be empty.")

    incidents = load_incidents(incident_path)
    incident = _find_incident(incidents, incident_id)
    incident["timeline"].append({
        "timestamp": _timestamp(),
        "entry_type": entry_type.strip() or "Investigation note",
        "note": note,
    })
    incident["updated_at"] = _timestamp()
    _write_incidents(incidents, incident_path)
    return incident


def associate_scan(
    incident_id: str,
    scan: dict,
    incident_path: Path = INCIDENT_PATH,
) -> dict:
    """Attach a complete scan record to an incident for durable evidence."""
    scan_id = scan.get("scan_id") if isinstance(scan, dict) else None
    if not scan_id:
        raise ValueError("A saved scan with a scan ID is required.")

    incidents = load_incidents(incident_path)
    incident = _find_incident(incidents, incident_id)

    if any(item.get("scan_id") == scan_id for item in incident["associated_scans"]):
        raise ValueError("This scan is already associated with the incident.")

    incident["associated_scans"].append(scan)
    incident["timeline"].append({
        "timestamp": _timestamp(),
        "entry_type": "Evidence attached",
        "note": f"Associated scan {scan_id} ({scan.get('timestamp', 'unknown time')}).",
    })
    incident["updated_at"] = _timestamp()
    _write_incidents(incidents, incident_path)
    return incident


def update_incident(
    incident_id: str,
    status: str,
    resolution: str = "",
    incident_path: Path = INCIDENT_PATH,
) -> dict:
    """Update incident status and record status changes in the timeline."""
    if status not in INCIDENT_STATUSES:
        raise ValueError("Incident status is not supported.")

    resolution = resolution.strip()
    if status == "Resolved" and not resolution:
        raise ValueError("A resolution summary is required before resolving an incident.")

    incidents = load_incidents(incident_path)
    incident = _find_incident(incidents, incident_id)
    previous_status = incident.get("status", "Open")
    previous_resolution = incident.get("resolution", "")

    incident["status"] = status
    incident["resolution"] = resolution if status == "Resolved" else ""
    incident["updated_at"] = _timestamp()

    if previous_status != status:
        note = f"Status changed from {previous_status} to {status}."
        if status == "Resolved":
            note += f" Resolution: {resolution}"
        incident["timeline"].append({
            "timestamp": _timestamp(),
            "entry_type": "Status update",
            "note": note,
        })
    elif status == "Resolved" and previous_resolution != resolution:
        incident["timeline"].append({
            "timestamp": _timestamp(),
            "entry_type": "Resolution updated",
            "note": resolution,
        })

    _write_incidents(incidents, incident_path)
    return incident


def build_incident_report_html(incident: dict) -> str:
    """Build a self-contained HTML incident report."""
    escape = html.escape
    timeline_rows = "".join(
        "<tr>"
        f"<td>{escape(entry.get('timestamp', ''))}</td>"
        f"<td>{escape(entry.get('entry_type', ''))}</td>"
        f"<td>{escape(entry.get('note', ''))}</td>"
        "</tr>"
        for entry in incident.get("timeline", [])
    )

    scan_rows = "".join(
        "<tr>"
        f"<td>{escape(scan.get('timestamp', ''))}</td>"
        f"<td>{escape(scan.get('overall_status', 'Unknown'))}</td>"
        f"<td>{escape(scan.get('overall_finding', ''))}</td>"
        "</tr>"
        for scan in incident.get("associated_scans", [])
    )

    if not scan_rows:
        scan_rows = '<tr><td colspan="3">No scans associated.</td></tr>'

    resolution = incident.get("resolution") or "Not resolved."
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident Report - {escape(incident.get('title', 'Untitled'))}</title>
<style>
body {{ font-family: Arial, sans-serif; color: #202124; line-height: 1.5; max-width: 1100px; margin: 40px auto; padding: 0 24px; }}
h1, h2 {{ color: #1f2937; }}
.meta {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; background: #f3f4f6; padding: 16px; border-radius: 8px; }}
.meta strong {{ display: block; font-size: 12px; text-transform: uppercase; color: #555; }}
section {{ margin-top: 28px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ text-align: left; vertical-align: top; padding: 10px; border-bottom: 1px solid #ddd; }}
th {{ background: #f3f4f6; }}
td {{ overflow-wrap: anywhere; }}
@media print {{ body {{ margin: 12mm; }} }}
</style>
</head>
<body>
<h1>{escape(incident.get('title', 'Untitled incident'))}</h1>
<div class="meta">
<div><strong>Status</strong>{escape(incident.get('status', 'Open'))}</div>
<div><strong>Severity</strong>{escape(incident.get('severity', 'Medium'))}</div>
<div><strong>Created</strong>{escape(incident.get('created_at', ''))}</div>
</div>
<section><h2>Description</h2><p>{escape(incident.get('description', '')) or 'No description provided.'}</p></section>
<section><h2>Resolution</h2><p>{escape(resolution)}</p></section>
<section><h2>Associated scans</h2><table><thead><tr><th>Timestamp</th><th>Overall status</th><th>Finding</th></tr></thead><tbody>{scan_rows}</tbody></table></section>
<section><h2>Investigation timeline</h2><table><thead><tr><th>Timestamp</th><th>Entry</th><th>Details</th></tr></thead><tbody>{timeline_rows}</tbody></table></section>
</body>
</html>"""


def clear_incidents(incident_path: Path = INCIDENT_PATH) -> None:
    """Remove the local incident file if it exists."""
    if incident_path.exists():
        incident_path.unlink()
