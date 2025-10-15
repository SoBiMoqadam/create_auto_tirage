#!/usr/bin/env python3
"""CLI Entrypoint for AutoTriage"""
import argparse
from core import aggregator, triage, report

def parse_args():
    p = argparse.ArgumentParser(description="AutoTriage — aggregate & triage security scan outputs")
    p.add_argument("--nmap", help="Path to nmap XML file")
    p.add_argument("--burp", help="Path to Burp JSON/CSV file")
    p.add_argument("--recon", help="Path to recon JSON file")
    p.add_argument("--out", default="reports/report.html", help="HTML report output path")
    p.add_argument("--json", default="reports/summary.json", help="Summary JSON output path")
    p.add_argument("--min-score", type=int, default=30, help="Minimum score to include in high-risk section")
    return p.parse_args()

def main():
    args = parse_args()
    data = {}
    if args.nmap:
        print(f"[+] Parsing nmap: {args.nmap}")
        data.setdefault('nmap', []).append(aggregator.parse_nmap(args.nmap))
    if args.burp:
        print(f"[+] Parsing burp: {args.burp}")
        data.setdefault('burp', []).append(aggregator.parse_burp(args.burp))
    if args.recon:
        print(f"[+] Parsing recon: {args.recon}")
        data.setdefault('recon', []).append(aggregator.parse_recon(args.recon))

    print("[+] Running triage rules...")
    summary = triage.run_triage(data)
    print("[+] Rendering report...")
    report.render_html(summary, args.out, min_score=args.min_score)
    report.write_json(summary, args.json)
    print(f"[+] Report written: {args.out}")
    print(f"[+] Summary JSON: {args.json}")

if __name__ == '__main__':
    main()
