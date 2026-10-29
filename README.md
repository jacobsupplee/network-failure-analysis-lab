# Network Failure Analysis Lab

This is a small Python project I built to practice troubleshooting common network problems.

It checks IP configuration, DNS, connectivity, routing, TCP ports, Windows Firewall profile settings, and possible outbound firewall rule matches for a target TCP connection. It can also look at the results together to help narrow down what might be wrong and what to check next.

## What you can try

- Run example DHCP and DNS problems.
- Run a combined scan of the example scenarios.
- Check your own computer's network, inspect Windows Firewall profile status and possible outbound rule matches, and test a hostname and TCP port.
- Review the findings and suggested next steps.

## Run it locally

You'll need Python installed.

Install the project dependencies:

```powershell
pip install -r dependencies.txt
```

Start the app:

```powershell
python -m streamlit run application.py
```

The app will open in your browser. Choose a diagnostic from the menu to get started.

## Run the tests

```powershell
python -m pytest
```

The live scan checks the network of the computer running the app, so results can vary depending on your connection and the host or port you test. Windows Firewall inspection uses read-only PowerShell commands. The connection-specific rule check lists enabled outbound rules whose collected destination address and port filters overlap the target; it does not fully simulate rule precedence, application/service filters, or prove that a rule blocked traffic. The tool does not change firewall settings.
