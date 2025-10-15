"""Parsers that convert tool outputs into a common internal format."""
from typing import Dict, Any, List
from lxml import etree
import json

def parse_nmap(path: str) -> Dict[str, Any]:
    """Parse nmap XML and return {'hosts': [{host, ip, ports:[{port, proto, service}]}]}"""
    tree = etree.parse(path)
    root = tree.getroot()
    hosts = []
    for h in root.findall('host'):
        addr = h.find('address')
        ip = addr.get('addr') if addr is not None else None
        hostname_elem = h.find('hostnames/hostname')
        host_name = hostname_elem.get('name') if hostname_elem is not None else ip
        ports = []
        for p in h.findall('ports/port'):
            portid = int(p.get('portid'))
            proto = p.get('protocol')
            state = p.find('state').get('state') if p.find('state') is not None else 'unknown'
            service_elem = p.find('service')
            service = service_elem.get('name') if service_elem is not None else ''
            if state == 'open':
                ports.append({'port': portid, 'proto': proto, 'service': service})
        hosts.append({'host': host_name, 'ip': ip, 'ports': ports})
    return {'tool': 'nmap', 'hosts': hosts}

def parse_burp(path: str) -> Dict[str, Any]:
    """Attempt to parse Burp JSON (if JSON) or fallback to simple CSV lines with columns: issue,host,param,detail"""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Expecting Burp JSON issues array
        issues = []
        for it in data.get('issues', []) if isinstance(data, dict) else data:
            issues.append({
                'name': it.get('name'),
                'severity': it.get('severity'),
                'host': it.get('host'),
                'path': it.get('path'),
                'detail': it.get('issueBackground') or it.get('issueDetail') or ''
            })
        return {'tool': 'burp', 'issues': issues}
    except Exception:
        # fallback: parse CSV-like
        issues = []
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 3:
                    issues.append({'name': parts[0], 'host': parts[1], 'detail': ','.join(parts[2:])})
        return {'tool': 'burp', 'issues': issues}

def parse_recon(path: str) -> Dict[str, Any]:
    """Simple recon JSON format expected: {subdomains: [...], headers: {...}}"""
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return {'tool': 'recon', 'data': data}
