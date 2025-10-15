"""Render HTML report and write JSON summary."""
from jinja2 import Template
import json
from typing import Dict, Any

TEMPLATE = """        <html>
<head>
  <meta charset="utf-8" />
  <title>AutoTriage Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .high { background: #ffe6e6; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; }
    th { background: #222; color: white; }
  </style>
</head>
<body>
  <h1>AutoTriage Report</h1>
  <p>Total findings: {{ summary.total_findings }}</p>

  <h2>Top Findings</h2>
  <table>
    <tr><th>Score</th><th>Type</th><th>Host/Name</th><th>Details</th><th>Source</th></tr>
    {% for f in summary.findings %}
    <tr class="{{ 'high' if f.score >= 60 else '' }}">
      <td>{{ f.score }}</td>
      <td>{{ f.type }}</td>
      <td>{{ f.get('host') or f.get('name') or f.get('ip') }}</td>
      <td>
        {% if f.type == 'open-port' %}
          Port: {{ f.port }} ({{ f.service }})
        {% elif f.type == 'vuln' %}
          {{ f.name }} - {{ f.path }}<br/>{{ f.detail }}
        {% else %}
          {{ f.get('detail') or '' }}
        {% endif %}
      </td>
      <td>{{ f.source }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""

def render_html(summary: Dict[str, Any], out_path: str, min_score: int = 30):
    tpl = Template(TEMPLATE)
    html = tpl.render(summary=summary)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)

def write_json(summary: Dict[str, Any], out_path: str):
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
