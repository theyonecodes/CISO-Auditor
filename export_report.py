import json
import os
import csv
import io
from datetime import datetime

REPORT_DIR = os.path.dirname(os.path.abspath(__file__))

def _count_by_category(checks):
    cats = {}
    for c in checks:
        cats.setdefault(c.category, {"pass": 0, "fail": 0, "warning": 0, "pending": 0, "total": 0})
        cats[c.category]["total"] += 1
        s = c.status.lower()
        if "pass" in s:
            cats[c.category]["pass"] += 1
        elif "fail" in s:
            cats[c.category]["fail"] += 1
        elif "warning" in s:
            cats[c.category]["warning"] += 1
        else:
            cats[c.category]["pending"] += 1
    return cats

def _status_color(status):
    return {"PASS": "#3FB950", "FAIL": "#F85149", "WARNING": "#D29922", "PENDING": "#8B949E"}.get(status, "#FFF")

def generate_html(checks):
    cats = _count_by_category(checks)
    total = len(checks)
    passed = sum(v["pass"] for v in cats.values())
    failed = sum(v["fail"] for v in cats.values())
    warned = sum(v["warning"] for v in cats.values())
    pending = sum(v["pending"] for v in cats.values())
    score = round((passed / total) * 100, 1) if total else 0

    def cat_rows():
        rows = ""
        for cat, counts in cats.items():
            pct = round((counts["pass"] / counts["total"]) * 100, 1)
            rows += f"""<tr>
                <td>{cat}</td>
                <td style="color:#3FB950">{counts["pass"]}</td>
                <td style="color:#F85149">{counts["fail"]}</td>
                <td style="color:#D29922">{counts["warning"]}</td>
                <td style="color:#8B949E">{counts["pending"]}</td>
                <td>{pct}%</td>
            </tr>"""
        return rows

    def check_rows():
        rows = ""
        for c in checks:
            color = _status_color(c.status)
            cls = c.status.lower()
            rows += f"""<tr class="{cls}">
                <td>#{c.id:03d}</td>
                <td>{c.category}</td>
                <td>{c.name}</td>
                <td class="status-cell" style="color:{color};font-weight:bold">{c.status}</td>
                <td>{c.details}</td>
            </tr>"""
        return rows

    cats_json = json.dumps(list(cats.keys()))

    JS_CODE = f"""
const categories = {cats_json};
const catSel = document.getElementById('catFilter');
categories.forEach(c => {{ const o = document.createElement('option'); o.value = c; o.textContent = c; catSel.appendChild(o); }});
let activeFilter = 'all';
function filterBy(status) {{
    activeFilter = status;
    document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
    const lookup = {{'all':'btn-all','pass':'btn-pass','fail':'btn-fail','warning':'btn-warn','pending':'btn-pend'}};
    const btn = document.getElementById(lookup[status]);
    if (btn) btn.classList.add('active');
    applyFilters();
}}
function applyFilters() {{
    const q = document.getElementById('search').value.toLowerCase();
    const cat = document.getElementById('catFilter').value;
    const rows = document.querySelectorAll('#findings-table tr.pass, #findings-table tr.fail, #findings-table tr.warning, #findings-table tr.pending');
    let shown = 0;
    rows.forEach(r => {{
        const text = r.textContent.toLowerCase();
        const status = r.classList[0];
        const match = (activeFilter === 'all' || status === activeFilter) &&
                      (!cat || r.cells[1].textContent === cat) &&
                      (!q || text.includes(q));
        r.classList.toggle('hidden', !match);
        if (match) shown++;
    }});
    document.getElementById('rowCount').textContent = 'Showing ' + shown + ' of {total}';
}}
filterBy('all');
"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CISO Advanced Security Auditor - Report</title>
<style>
body {{ background:#0D1117; color:#C9D1D9; font-family:'Segoe UI',Arial,sans-serif; margin:40px; }}
h1,h2,h3 {{ color:#58A6FF; }}
.summary {{ display:flex; gap:20px; margin:20px 0; flex-wrap:wrap; }}
.card {{ background:#161B22; border:1px solid #30363D; border-radius:8px; padding:20px; flex:1; text-align:center; min-width:100px; cursor:pointer; }}
.card .num {{ font-size:36px; font-weight:bold; }}
.score {{ font-size:48px; font-weight:bold; text-align:center; }}
.filters {{ display:flex; gap:10px; margin:15px 0; flex-wrap:wrap; align-items:center; }}
.filters input,.filters select {{ background:#0D1117; color:#C9D1D9; border:1px solid #30363D; padding:8px 12px; border-radius:4px; font-family:inherit; }}
.filters button {{ background:#21262D; color:#C9D1D9; border:1px solid #30363D; padding:8px 16px; border-radius:4px; cursor:pointer; font-family:inherit; }}
.filters button:hover {{ background:#30363D; }}
.filters button.active {{ border-color:#58A6FF; }}
.filters .count {{ color:#8B949E; font-size:13px; margin-left:auto; }}
table {{ width:100%; border-collapse:collapse; margin:20px 0; }}
th {{ background:#161B22; color:#58A6FF; padding:10px; text-align:left; border-bottom:2px solid #30363D; position:sticky; top:0; }}
td {{ padding:8px 10px; border-bottom:1px solid #21262D; }}
tr:hover {{ background:#161B22; }}
.hidden {{ display:none !important; }}
.footer {{ margin-top:30px; color:#8B949E; font-size:12px; text-align:center; }}
</style>
</head>
<body>
<h1>CISO Advanced Security Auditor — Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="score" style="color:#58A6FF">{score}% SECURE</div>
<div class="summary">
<div class="card" onclick="filterBy('pass')"><div class="num" style="color:#3FB950">{passed}</div>PASS</div>
<div class="card" onclick="filterBy('fail')"><div class="num" style="color:#F85149">{failed}</div>FAIL</div>
<div class="card" onclick="filterBy('warning')"><div class="num" style="color:#D29922">{warned}</div>WARNING</div>
<div class="card" onclick="filterBy('pending')"><div class="num" style="color:#8B949E">{pending}</div>PENDING</div>
</div>
<h2>Domain Summary</h2>
<table id="domain-table">
<tr><th>Domain</th><th>PASS</th><th>FAIL</th><th>WARNING</th><th>PENDING</th><th>Score</th></tr>
{cat_rows()}
</table>
<h2>Detailed Findings ({total} checks)</h2>
<div class="filters">
<input type="text" id="search" placeholder="Search checks..." onkeyup="applyFilters()">
<select id="catFilter" onchange="applyFilters()">
<option value="">All Domains</option>
</select>
<button onclick="filterBy('pass')" id="btn-pass">PASS</button>
<button onclick="filterBy('fail')" id="btn-fail">FAIL</button>
<button onclick="filterBy('warning')" id="btn-warn">WARNING</button>
<button onclick="filterBy('pending')" id="btn-pend">PENDING</button>
<button onclick="filterBy('all')" id="btn-all">ALL</button>
<span class="count" id="rowCount">Showing {total} of {total}</span>
</div>
<div style="max-height:600px;overflow-y:auto">
<table id="findings-table">
<tr><th>ID</th><th>Domain</th><th>Check</th><th>Status</th><th>Details</th></tr>
{check_rows()}
</table>
</div>
<div class="footer">CISO Advanced Security Auditor — Automated Report</div>
<script>{JS_CODE}</script>
</body>
</html>"""
    return html

def generate_csv(checks):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Domain", "Check Name", "Status", "Details"])
    for c in checks:
        writer.writerow([c.id, c.category, c.name, c.status, c.details])
    return output.getvalue()

def generate_json(checks):
    cats = _count_by_category(checks)
    total = len(checks)
    passed = sum(v["pass"] for v in cats.values())
    score = round((passed / total) * 100, 1) if total else 0

    data = {
        "report_metadata": {
            "tool": "CISO Advanced Security Auditor",
            "generated": datetime.now().isoformat(),
            "total_checks": total,
            "security_score": score,
        },
        "summary": {
            "passed": passed,
            "failed": sum(v["fail"] for v in cats.values()),
            "warnings": sum(v["warning"] for v in cats.values()),
            "pending": sum(v["pending"] for v in cats.values()),
        },
        "categories": {
            cat: {
                "passed": counts["pass"],
                "failed": counts["fail"],
                "warnings": counts["warning"],
                "pending": counts["pending"],
                "total": counts["total"],
            }
            for cat, counts in cats.items()
        },
        "findings": [
            {
                "id": c.id,
                "category": c.category,
                "name": c.name,
                "status": c.status,
                "details": c.details,
            }
            for c in checks
        ],
    }
    return json.dumps(data, indent=2)

FORMATS = {
    "html": {"ext": ".html", "gen": generate_html, "desc": "HTML Report"},
    "json": {"ext": ".json", "gen": generate_json, "desc": "JSON Data"},
    "csv":  {"ext": ".csv",  "gen": generate_csv,  "desc": "CSV Spreadsheet"},
}

def save_report(checks, fmt="html", filepath=None):
    if fmt not in FORMATS:
        raise ValueError(f"Unknown format: {fmt}. Use one of: {', '.join(FORMATS)}")
    fmt_info = FORMATS[fmt]
    content = fmt_info["gen"](checks)
    if filepath is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(REPORT_DIR, f"CISO_Audit_Report_{ts}{fmt_info['ext']}")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath
