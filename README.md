# AutoTriage — Report Generator & Auto-Triage for Bug Bounty

> Automated aggregator that ingests outputs from multiple security tools
> (nmap XML, Burp JSON/CSV, recon JSON) and produces a prioritized HTML report
> and a machine-readable summary JSON.

---

## Overview

**AutoTriage** combines parsing, normalization, and simple rule-based scoring to turn noisy scanner outputs into actionable, prioritized findings.  
Built for bug bounty hunters, red teams, and security automation pipelines — lightweight, extensible, and CI-friendly.

**Tech stack:** Python 3.10+, Jinja2 for HTML reports, simple rule engine for triage.

---

## Features

- Parse `nmap` XML output (ports, services, scripts)
- Parse Burp Scanner exports (JSON and CSV)
- Accept recon JSON (subdomains, HTTP headers, basic probes)
- Rule-based auto-triage with configurable risk scoring
- Generate human-readable HTML report (Jinja2) + machine-readable summary JSON
- Dockerfile included for containerized runs
- GitHub Actions CI template for linting, tests, and artifact generation

---

## Why AutoTriage?

- Reduce noise: Normalize different scanners' outputs into one canonical format.  
- Prioritize faster: Rule-based scoring highlights high-value findings first.  
- Pipeline-friendly: Produce both HTML and JSON outputs for human review and automated tooling.  
- Easy to extend: Add parsers, triage rules, or exporters without touching core logic.

---

## Quickstart

```bash
# clone & setup
git clone https://github.com/<your-username>/auto-triage.git
cd auto-triage

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# example run (merge multiple inputs)
python cli.py --nmap examples/sample_nmap.xml \
              --burp examples/sample_burp.json \
              --recon examples/sample_recon.json \
              --out reports/report.html \
              --summary reports/summary.json
```

---

## Input formats supported

- **Nmap XML** (`nmap -oX`)
- **Burp Scanner JSON** (export) and **Burp CSV**
- **Recon JSON** (simple schema — subdomains, titles, headers)

If you need additional formats, implement a new parser under `parsers/` and register it in `cli.py`.

---

## Output

- `reports/report.html` — Human-friendly, sectioned report with summary, host details, and prioritized issues.  
- `reports/summary.json` — Canonical, machine-readable summary with per-finding metadata and triage score.

Each finding in `summary.json` contains:
```json
{
  "id": "unique-id",
  "source": "nmap|burp|recon",
  "host": "example.com",
  "port": 80,
  "service": "http",
  "title": "Description",
  "details": "...",
  "severity": "low|medium|high|critical",
  "score": 85,
  "evidence": ["..."],
  "timestamp": "2025-10-17T12:34:56Z"
}
```

---

## Triage rules

Triage logic lives in `triage/rules.py`. Rules are simple, composable, and prioritized. Examples:

- `open_http_admin_panel` → +40 if path contains `/admin` and port is 80/443
- `high_risk_banner` → +30 if service banner matches known vulnerable version
- `burp_confidence_high` → +20 if Burp issue confidence == "Certain"

Scores are normalized to a 0–100 scale and mapped to `severity` buckets. Customize rules to match your program's risk model.

---

## Extensibility

- **Add a parser**: drop a new parser in `parsers/` and expose it via CLI.
- **Add output formats**: create exporters in `exporters/` (CSV, SARIF, Markdown).
- **Integrate**: hook the JSON summary into dashboards or triage queues.
- **Testing**: keep `examples/` and `tests/` to simulate scanner outputs offline.

---

## Docker

Quick run without Python env:

```bash
# build
docker build -t auto-triage:latest .

# run (mount your input directory)
docker run --rm -v $(pwd)/examples:/work/examples -v $(pwd)/reports:/work/reports auto-triage:latest \
  --nmap /work/examples/sample_nmap.xml --burp /work/examples/sample_burp.json --out /work/reports/report.html
```

---

## CI / GitHub Actions

A sample workflow is placed at `.github/workflows/ci.yml`. It covers:
- checkout
- set up Python 3.10
- install dependencies
- lint (flake8) and format (black)
- run unit tests
- optionally run a lightweight, non-networked aggregation job against `examples/` and upload `report.html` as an artifact

**Important:** CI must **never** perform scans against external targets. Use canned inputs for automation.

---

## Security & Responsible Use

AutoTriage processes potentially sensitive scan outputs. Use it responsibly:

- Only process data for targets you are authorized to test.
- Sanitize and protect exported reports (they may contain sensitive endpoints).
- Rate-limit any automated follow-up tooling that may perform active scanning.

---

## Project layout (suggested)

```
.
├── cli.py
├── parsers/
│   ├── nmap.py
│   ├── burp.py
│   └── recon.py
├── triage/
│   ├── rules.py
│   └── engine.py
├── exporters/
│   ├── html.py
│   └── json.py
├── samples/
│   ├── sample_nmap.xml
│   └── sample_burp.json
├── tests/
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## Contribution guidelines

- Fork the repo and open a feature branch.
- Write clear commit messages (`feat:`, `fix:`, `docs:`).
- Add tests for new parsers or triage rules.
- Respect responsible disclosure when sharing reports or examples.

---

## Suggested commit messages

```
feat: add burp json parser and mapping
fix: normalize nmap service names to lowercase
docs: add triage rule examples
test: add samples for nmap and burp
```

---

## License

MIT — see `LICENSE` file.

---

**Disclaimer:** Only analyze scan outputs for assets you own or have explicit permission to test. Misuse of scanning tools and report distribution may violate laws or program terms.
