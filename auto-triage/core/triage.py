"""Simple rule-based triage engine.

Input: dictionary with keys like 'nmap', 'burp', 'recon' mapping to lists of parsed outputs.
Output: summary dict with scored findings.
"""
from typing import Dict, Any, List
import collections

DEFAULT_RULES = [
    # (rule_name, weight, matcher_func) -- matcher returns list of findings
]

def run_triage(data: Dict[str, Any]) -> Dict[str, Any]:
    findings = []
    # Nmap rules
    for n in data.get('nmap', []):
        for host in n.get('hosts', []):
            for p in host.get('ports', []):
                port = p.get('port')
                svc = p.get('service', '')
                score = 0
                # scoring heuristic
                if port in (22, 3389, 3306, 5432, 6379):
                    score += 60
                if svc and any(x in svc.lower() for x in ('http','ssh','mysql','microsoft-ds','rdp')):
                    score += 10
                if score > 0:
                    findings.append({
                        'type': 'open-port',
                        'host': host.get('host'),
                        'ip': host.get('ip'),
                        'port': port,
                        'service': svc,
                        'score': score,
                        'source': 'nmap'
                    })
    # Burp rules
    for b in data.get('burp', []):
        for issue in b.get('issues', []):
            sev = issue.get('severity') or ''
            name = issue.get('name') or 'issue'
            score = 0
            if sev.lower() in ('high','critical'):
                score += 80
            elif sev.lower() == 'medium':
                score += 40
            else:
                score += 10
            # heuristics for XSS/SQLi etc
            if 'xss' in (name or '').lower():
                score += 30
            if 'sql' in (name or '').lower():
                score += 30
            findings.append({
                'type': 'vuln',
                'name': name,
                'host': issue.get('host'),
                'path': issue.get('path'),
                'detail': issue.get('detail'),
                'score': score,
                'source': 'burp'
            })
    # Recon rules: newly discovered subdomains -> medium score
    for r in data.get('recon', []):
        d = r.get('data', {})
        subs = d.get('subdomains') or d.get('hosts') or []
        for s in subs:
            findings.append({
                'type': 'subdomain',
                'name': s,
                'score': 20,
                'source': 'recon'
            })

    # aggregate & sort
    findings_sorted = sorted(findings, key=lambda x: x.get('score', 0), reverse=True)
    summary = {'total_findings': len(findings_sorted), 'findings': findings_sorted}
    return summary
