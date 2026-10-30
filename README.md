# Network Failure Analysis Lab

A Python and Streamlit project for investigating common network problems. The application collects network information, runs diagnostic checks, and brings the results together to help identify what to investigate next.

**Author:** Jacob Supplee  
**Technologies:** Python, Streamlit, PowerShell, pytest

[![Tests](https://github.com/jacobsupplee/network-failure-analysis-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/jacobsupplee/network-failure-analysis-lab/actions/workflows/tests.yml)

## Overview

The project is designed around a simple troubleshooting process: collect evidence, check individual parts of the network, compare the results, and decide what to test next.

The **Live Network Scan** runs seven checks:

1. **DHCP and IP configuration** — reviews adapter addressing, DHCP information, and signs of an APIPA address.
2. **DNS resolution** — checks whether a hostname resolves.
3. **Connectivity** — tests reachability of the default gateway and an external target.
4. **IPv4 routing** — reviews the routing table and default route.
5. **TCP connectivity** — tests a hostname or IP address on a selected port.
6. **Windows Firewall profiles** — checks the status of the Domain, Private, and Public profiles.
7. **Outbound firewall rules** — checks whether collected filters from enabled outbound block rules may match the selected TCP target.

The correlation layer combines the diagnostic results, identifies possible failure areas, ranks troubleshooting priorities, and flags conflicting observations. The priority score is intended to help order an investigation; it is not a probability or a confirmed root cause.

## Other features

- **Example scenarios:** Run bundled DHCP, DNS, TCP, and routing scenarios without having to create an actual network failure.
- **Scan history:** Save and review previous live scans, then compare their diagnostic results.
- **Network baseline:** Save a verified network configuration and compare later scans for changes.
- **Incident management:** Track an issue, add investigation notes, attach scan evidence, and document its resolution.
- **Troubleshooting playbooks:** Follow guided procedures for DHCP, DNS, and routing issues. Commands are provided for manual use and are not executed by the application.
- **Diagnostic reports:** Export a saved scan as an HTML report or JSON evidence file.

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

Choose an individual scenario from the diagnostic-mode selector or use **Combined scan** to run them together. The application compares each result with the scenario's expected status and reports mismatches. These scenarios use sample evidence, so they can be run without changing the computer's network settings.

## Running the application

### Requirements

- Python 3.10 or newer
- Windows for the complete live scan and its PowerShell-based collectors
- Network access for live DNS and connectivity checks

Some analysis and scenario functionality can be used outside Windows, but the full live collection process is designed for Windows.

### Setup

Open PowerShell in the project directory. Create and activate a virtual environment if you want to keep the project dependencies separate.

Install the dependencies:

```powershell
python -m pip install -r dependencies.txt
```

Start the application:

```powershell
python -m streamlit run application.py
```

Streamlit will provide a local URL to open in your browser. Select a diagnostic mode from the application. For **Live Network Scan**, enter the hostname or IP address and TCP port you want to test.

### Running the tests

Run the test suite from the project directory:

```powershell
python -m pytest
```

GitHub Actions also runs the tests on pushes and pull requests, with Linux and Windows jobs.

## Project structure

```text
network-failure-analysis-lab/
├── application.py
├── dependencies.txt
├── scenarios/
├── src/
│   ├── analyzers/
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

A few of the main components:

- `application.py` contains the Streamlit interface and coordinates live scans.
- `src/evidence_collection.py` collects network and Windows Firewall information.
- `src/analyzers/` contains the individual diagnostic checks.
- `src/correlation*.py` combines findings, tracks evidence references, handles conflicts, and ranks troubleshooting priorities.
- `src/diagnostic_report.py` builds the HTML and JSON diagnostic exports.
- `scenarios/` contains the sample diagnostic scenarios.
- `tests/` contains the automated tests.

## Data and privacy

Scan history, network baselines, and incident records are stored locally in the `data/` directory. These files are excluded from Git because they can contain IP addresses, DNS settings, firewall information, and investigation notes.

Diagnostic reports can contain the same information. Review exported files before sharing them.

## Limitations

- Diagnostic findings are based on the evidence available at the time of a scan. They do not automatically prove a root cause.
- A TCP timeout does not, by itself, establish whether the problem is filtering, routing, or an unavailable service.
- Outbound firewall analysis checks for possible filter overlap. It is not a complete simulation of Windows Firewall policy evaluation.
- The troubleshooting playbooks display commands for a technician to review and run. The application does not execute those commands or make network configuration changes.
- Live results depend on the computer, network, permissions, and selected test target.
- The bundled scenarios are sample cases. Testing against a simulated network and real failure conditions is a separate part of the project's development.

## Project goal

I built this project to get more practical experience with network troubleshooting, Python, PowerShell, evidence collection, and automated testing. It is also a way to practice documenting findings clearly and avoiding assumptions when the available evidence is incomplete.
