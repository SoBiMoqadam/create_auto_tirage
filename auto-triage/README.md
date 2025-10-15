# AutoTriage — Report Generator & Auto-Triage for Bug Bounty

Automated aggregator that ingests outputs from multiple security tools
(nmap XML, Burp JSON/CSV, recon JSON) and produces a prioritized HTML report
and machine-readable summary JSON.

## Features
- Parse `nmap` XML output (ports/services)
- Parse Burp Scanner JSON/CSV issues
- Accept recon JSON (subdomains, headers)
- Simple rule-based auto-triage (risk scoring)
- HTML report (Jinja2) + summary JSON output
- Dockerfile & GitHub Actions CI template

## Quickstart

```bash
# create venv and install
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# run aggregator (example)
python cli.py --nmap examples/sample_nmap.xml \
              --burp examples/sample_burp.json \
              --recon examples/sample_recon.json \
              --out reports/report.html
```

## Input formats supported
- Nmap XML (default nmap -oX)
- Burp Scanner JSON (export) or simple Burp CSV
- Recon JSON (simple format produced by recon scripts)

## Extensibility
- Add new parsers in `parsers/`
- Add triage rules in `triage/rules.py`
- Swap HTML report for a web UI later

## License
MIT

**Important:** Only analyze data for targets you have permission to test.
