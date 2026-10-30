# Network Failure Analysis Lab

A Python and Streamlit application for investigating common network problems. It collects network evidence, runs focused diagnostic checks, correlates findings, and helps organize the next steps in an investigation.

**Author:** Jacob Supplee  
**Technologies:** Python, Streamlit, PowerShell, pytest

[![Tests](https://github.com/jacobsupplee/network-failure-analysis-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/jacobsupplee/network-failure-analysis-lab/actions/workflows/tests.yml)

## Overview

The application follows an evidence-based troubleshooting process: collect information, evaluate individual network functions, correlate observations, and identify what should be investigated next.

The **Live Network Scan** runs seven checks:

1. **DHCP and IP configuration** — reviews adapter addressing, DHCP information, and signs of an APIPA address.
2. **DNS resolution** — checks whether a hostname resolves.
3. **Connectivity** — tests reachability of the default gateway and an external target.
4. **IPv4 routing** — reviews the routing table and default route.
5. **TCP connectivity** — tests a hostname or IP address on a selected port.
6. **Windows Firewall profiles** — checks the status of the Domain, Private, and Public profiles.
7. **Outbound firewall rules** — checks whether collected filters from enabled outbound block rules may match the selected TCP target.

The correlation layer combines diagnostic results, identifies possible failure areas, ranks troubleshooting priorities, and flags conflicting observations. A priority score helps order an investigation; it is not a probability or a confirmed root cause.

## Application features

- **Live Network Scan:** Collects local Windows network evidence and runs the seven diagnostic checks.
- **Example Scenarios:** Runs six bundled scenarios using sample evidence, without changing the computer's network settings.
- **Scan History:** Saves and reviews previous live scans, with comparisons between diagnostic results.
- **Network Baseline:** Saves a verified network configuration and compares later scans for changes.
- **Incident Management:** Tracks an issue, records investigation notes, attaches scan evidence, and documents resolution.
- **Troubleshooting Playbooks:** Provides guided procedures for DHCP, DNS, and routing issues. Commands are displayed for manual review and are not executed by the application.
- **Diagnostic Reports:** Exports saved scans as HTML reports or JSON evidence files.
- **Incident Reports:** Exports incident records and their investigation timeline as HTML.

## Example scenarios

The bundled scenarios provide repeatable examples of the analysis process:

| Scenario | What it demonstrates |
| --- | --- |
| DHCP-001 | A workstation receives an APIPA address |
| DNS-001 | A DNS query times out |
| TCP-001 | A TCP connection is refused |
| ROUTE-001 | The IPv4 default route is missing |
| ROUTE-002 | The reported gateway does not match the default route |
| ROUTE-003 | A healthy IPv4 routing configuration |

Open **Example Scenarios**, select a scenario, and click **Run Example Scenario**. The application compares the analysis with the scenario's expected result and reports whether they match. These scenarios use sample evidence and do not inspect or change the live network.

## Requirements

- Python 3.10 or newer
- Windows for the complete Live Network Scan and its PowerShell-based collectors
- Network access for live DNS and connectivity checks

The example scenarios and much of the analysis functionality can run on other operating systems. The full live collection workflow is designed for Windows.

## Run locally

Clone the repository and open the project directory:

```powershell
git clone https://github.com/jacobsupplee/network-failure-analysis-lab.git
cd network-failure-analysis-lab
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the project dependencies:

```powershell
python -m pip install -r dependencies.txt
```

Start the application:

```powershell
python -m streamlit run application.py
```

Streamlit will display a local URL to open in your browser. The application opens to a neutral home page; no diagnostic checks run until you select a tool and initiate an action.

## Run the tests

From the project directory, run:

```powershell
python -m pytest
```

GitHub Actions also runs the test suite on Linux and Windows. The Linux job additionally performs a Streamlit application startup smoke test.

## Project structure

```text
network-failure-analysis-lab/
├── application.py
├── dependencies.txt
├── requirements.txt
├── scenarios/
├── src/
│   ├── analyzers/
│   ├── analysis_runner.py
│   ├── evidence_collection.py
│   ├── correlation.py
│   ├── correlation_evidence.py
│   ├── correlation_scoring.py
│   ├── diagnostic_report.py
│   ├── incidents.py
│   ├── network_baseline.py
│   ├── playbooks.py
│   └── scan_history.py
├── tests/
└── .github/
    └── workflows/
        └── tests.yml
```

Key components:

- `application.py` contains the Streamlit interface and coordinates live scans.
- `src/evidence_collection.py` collects network and Windows Firewall information.
- `src/analyzers/` contains the individual diagnostic checks.
- `src/correlation*.py` combines findings, tracks evidence references, handles conflicts, and ranks troubleshooting priorities.
- `src/diagnostic_report.py` builds HTML and JSON diagnostic exports.
- `src/incidents.py`, `src/network_baseline.py`, and `src/scan_history.py` manage local investigation records.
- `scenarios/` contains the sample diagnostic scenarios.
- `tests/` contains the automated tests.

## Data and privacy

Scan history, network baselines, and incident records are stored locally in the `data/` directory. These files are excluded from Git because they can contain IP addresses, DNS settings, firewall information, and investigation notes.

Diagnostic and incident reports can contain the same information. Review exported files before sharing them. The application does not upload local scan records to a remote service.

## Limitations

- Diagnostic findings are based on the evidence available at the time of a scan. They do not automatically prove a root cause.
- A TCP timeout does not, by itself, establish whether the problem is filtering, routing, or an unavailable service.
- Outbound firewall analysis checks for possible filter overlap. It is not a complete simulation of Windows Firewall policy evaluation.
- Troubleshooting playbooks display commands for a technician to review and run. The application does not execute those commands or make network configuration changes.
- Live results depend on the computer, network, permissions, and selected test target.
- Bundled scenarios use sample evidence. Testing against a separately simulated network and real failure conditions is outside the scope of these examples.

## Project goal

This project was built to develop practical experience with network troubleshooting, Python, PowerShell, evidence collection, and automated testing. It emphasizes documenting findings clearly and avoiding assumptions when the available evidence is incomplete.
