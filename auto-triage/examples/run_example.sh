#!/bin/bash
python cli.py --nmap examples/sample_nmap.xml --burp examples/sample_burp.json --recon examples/sample_recon.json --out reports/report.html --json reports/summary.json
echo "Report generated: reports/report.html"
