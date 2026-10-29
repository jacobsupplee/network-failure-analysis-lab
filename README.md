# Network Failure Analysis Lab

An evidence-driven network troubleshooting application built with Python and Streamlit. It collects network observations, runs focused diagnostic analyzers, and correlates their findings to help prioritize the next troubleshooting step.

[![Tests](https://github.com/jacobsupplee/network-failure-analysis-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/jacobsupplee/network-failure-analysis-lab/actions/workflows/tests.yml)

## What it checks

The **Live Network Scan** runs seven diagnostic checks:

1. **DHCP and IP configuration** — inspects the primary adapter's IP address, default gateway, and DHCP information; identifies signs such as an APIPA address.
2. **DNS resolution** — checks whether a hostname resolves.
3. **Network connectivity** — checks reachability of the default gateway and an external target.
4. **IPv4 routing** — examines the routing table and default-route evidence.
5. **TCP connectivity** — attempts a connection to a configurable hostname/IP and TCP port.
6. **Windows Firewall profiles** — reports whether the Domain, Private, and Public profiles are enabled.
7. **Outbound firewall rule filters** — identifies enabled outbound block rules whose collected protocol, remote-address, and remote-port filters may match the chosen TCP target.

Each diagnostic reports its observations, finding, possible causes where supported, recommended tests, and verification steps. The correlation layer combines results, ranks troubleshooting priorities, and surfaces conflicting observations rather than silently treating them as consistent.

## Try the example scenarios

The project includes JSON scenarios for DHCP/APIPA, DNS, TCP, and IPv4 routing failures. These let you exercise the analysis flow without relying on a real network outage.

The test suite also covers routing, TCP outcomes, firewall rule matching, evidence collection parsing, scenario validation, and root-cause correlation.

## Example scenarios

| Scenario | Evidence provided | Expected result |
| --- | --- | --- |
| `DHCP-001` — Workstation receives an APIPA address | IPv4 address `169.254.12.34`, with no default gateway or DHCP server reported | `investigate` |
| `DNS-001` — DNS query times out | Hostname lookup times out against the recorded DNS server | `investigate` |
| `TCP-001` — Target service refuses TCP connections | Connection to `192.0.2.10:443` is refused | `investigate` |
| `ROUTE-001` — Missing default route | Routing table has a local subnet route but no IPv4 default route | `investigate` |
| `ROUTE-002` — Default gateway mismatch | Reported gateway `192.168.1.254` differs from the default route gateway `192.168.1.1` | `investigate` |

Run an individual scenario from the app's diagnostic-mode selector or choose **Combined scan** to run all bundled scenarios. The scenario runner compares the analyzer's actual status with `expected_status`; a mismatch is reported rather than treated as a passing scenario. These are synthetic examples, so they are repeatable without deliberately breaking the machine's network connection.

## Example diagnostic output

For the bundled DHCP scenario, the analyzer identifies the APIPA address and missing configuration evidence, then recommends specific checks rather than claiming a confirmed root cause.

```text
Status: investigate
Finding: The workstation has an APIPA address, and no default gateway and DHCP server was reported.
Possible causes:
- DHCP server unavailable or unreachable
- Client or network configuration issue

Recommended next tests:
- Check the network adapter and link state
- Run ipconfig /all
- Inspect DHCP server availability and scope
```

The wording above is illustrative; the application displays the full evidence, confidence labels, next steps, and verification checklist. An APIPA address is a clue that normal DHCP configuration may not have been received, not proof of which component failed.

## Requirements

- Python 3.10 or newer
- Windows for the full live scan, including the PowerShell-based Windows Firewall and network configuration collectors
- Internet or network access for live connectivity tests

Some analyzers and scenario tests can run on other platforms, but the full live collection path is designed for Windows.

## Run locally

Open PowerShell in the project directory and activate your virtual environment if you use one.

Install dependencies:

```powershell
python -m pip install -r dependencies.txt
```

Start the Streamlit app:

```powershell
python -m streamlit run application.py
```

Choose a diagnostic mode in the browser. For **Live Network Scan**, enter the hostname or IP address and TCP port you want to test, then run the scan.

## Run tests

```powershell
python -m pytest
```

GitHub Actions runs the test suite when changes are pushed to the repository.

## Architecture

- `application.py` — Streamlit interface and live-scan orchestration
- `src/evidence_collection.py` — read-only collection of network and firewall evidence
- `src/analyzers/` — focused analyzers for DHCP, DNS, connectivity, routing, TCP ports, and firewall data
- `src/correlation.py` and supporting correlation modules — evidence correlation, conflict handling, confidence labels, and troubleshooting-priority scoring
- `src/scenario_loader.py` and `src/analysis_runner.py` — scenario validation and execution
- `scenarios/` — bundled JSON example scenarios
- `tests/` — automated unit and integration-style tests

## Important limitations

- A diagnostic result is an observation, not automatic proof of root cause. Correlation ranks what to investigate; its priority score is **not a probability**.
- Outbound firewall analysis is a filter-overlap check, not a complete Windows Firewall policy simulator. It does not fully evaluate profile applicability, application/service constraints, policy precedence, or every Windows filtering behavior.
- Firewall inspection uses read-only commands and does not change firewall settings.
- Live results depend on the current machine, network, DNS, permissions, and target host/port. A timeout or failed connection can have causes outside the local computer.
- The bundled scenarios are controlled examples, not a substitute for validating behavior against a real network environment.

## Project goal

This project is a practical exercise in Python, network troubleshooting, evidence collection, automated testing, and explaining diagnostic uncertainty clearly.
