import json
import os
import csv
import io
from datetime import datetime

REPORT_DIR = os.path.dirname(os.path.abspath(__file__))

def _format_timestamp():
    return datetime.now().strftime("%B %d, %Y at %I:%M:%S %p")

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
<p>Generated: {_format_timestamp()}</p>
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

def generate_ps1(checks):
    lines = [
        "# CISO Advanced Security Auditor — Remediation Script",
        f"# Generated: {_format_timestamp()}",
        "# Run as Administrator",
        "",
        "Write-Host 'CISO Security Remediation Script' -ForegroundColor Cyan",
        "Write-Host '==================================' -ForegroundColor Cyan",
        "",
    ]
    fixable = [c for c in checks if c.status in ("FAIL", "WARNING") and c.auto_fixable]
    if not fixable:
        lines.append("# No auto-fixable items found.")
    else:
        lines.append(f"# {len(fixable)} auto-fixable items detected")
        lines.append("")
        for c in fixable:
            lines.append(f"# --- Check #{c.id:03d}: {c.name} ---")
            lines.append(f"# Status: {c.status}")
            lines.append(f"# Details: {c.details}")
            lines.append(f"# Remediation: {c.remediation}")
            lines.append("")
    lines.append("Write-Host 'Review each step before executing.' -ForegroundColor Yellow")
    lines.append("")
    lines.append("Read-Host -Prompt 'Press Enter to exit'")
    return "\n".join(lines)

def generate_pdf(checks):
    import io
    buf = io.BytesIO()
    def w(s):
        buf.write(s.encode("latin-1", errors="replace"))
    def obj_start(n):
        w(f"{n} 0 obj\n")
    def obj_end():
        w("endobj\n")

    cats = _count_by_category(checks)
    total = len(checks)
    passed = sum(v["pass"] for v in cats.values())
    failed = sum(v["fail"] for v in cats.values())
    warned = sum(v["warning"] for v in cats.values())
    pending = sum(v["pending"] for v in cats.values())
    score = round((passed / total) * 100, 1) if total else 0

    lines_out = []
    y = 750
    LINE = 14
    def add_line(text, size=10, bold=False):
        nonlocal y
        if y < 60:
            lines_out.append((text, size, bold, 750))
            y = 750 - LINE
        else:
            lines_out.append((text, size, bold, y))
            y -= LINE

    add_line("CISO Advanced Security Auditor", size=18, bold=True)
    add_line(f"Security Audit Report", size=14, bold=True)
    add_line(f"Generated: {_format_timestamp()}", size=9)
    add_line("")
    add_line(f"Security Score: {score}%", size=14, bold=True)
    add_line("")
    add_line(f"PASS: {passed}    FAIL: {failed}    WARNING: {warned}    PENDING: {pending}", size=11, bold=True)
    add_line(f"Total Checks: {total}", size=10)
    add_line("")
    add_line("Domain Summary", size=13, bold=True)
    add_line("")
    for cat, counts in cats.items():
        pct = round((counts["pass"] / counts["total"]) * 100, 1)
        add_line(f"  {cat}: {counts['pass']}/{counts['total']} pass ({pct}%)", size=9)
    add_line("")
    add_line("Detailed Findings", size=13, bold=True)
    add_line("")
    for c in checks:
        add_line(f"#{c.id:03d}  {c.name}  [{c.status}]", size=9, bold=True)
        add_line(f"    {c.details}", size=8)
        if c.remediation:
            add_line(f"    Remediation: {c.remediation}", size=8)
        add_line("")

    page_lines = []
    pages = []
    current_page = []
    current_y = 750
    for text, size, bold, _ in lines_out:
        if current_y < 60:
            pages.append(current_page)
            current_page = []
            current_y = 750
        current_page.append((text, size, bold, current_y))
        current_y -= LINE
    if current_page:
        pages.append(current_page)

    obj_num = 1
    objs = {}
    objs[obj_num] = f"{obj_num} 0 obj\n<< /Type /Catalog /Pages {obj_num+1} 0 R >>\nendobj\n"
    obj_num += 1

    page_refs = []
    for pi in range(len(pages)):
        obj_num += 1
        page_refs.append(f"{obj_num} 0 R")
        objs[obj_num] = f"{obj_num} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {obj_num+1} 0 R /Resources << /Font << /F1 {len(pages)*2+3} 0 R /F2 {len(pages)*2+4} 0 R >> >> >>\nendobj\n"

        stream_lines = ["BT"]
        for text, size, bold, py in pages[pi]:
            font = "/F2" if bold else "/F1"
            safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            stream_lines.append(f"{font} {size} Tf 40 {py} Td ({safe}) Tj ET")
            stream_lines.append("BT")
        stream_lines.append("ET")
        stream = "\n".join(stream_lines)

        obj_num += 1
        objs[obj_num] = f"{obj_num} 0 obj\n<< /Length {len(stream)} >>\nstream\n{stream}\nendstream\nendobj\n"

    kids_str = " ".join(page_refs)
    objs[2] = f"2 0 obj\n<< /Type /Pages /Kids [{kids_str}] /Count {len(pages)} >>\nendobj\n"

    obj_num += 1
    objs[obj_num] = f"{obj_num} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
    font1_obj = obj_num
    obj_num += 1
    objs[obj_num] = f"{obj_num} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n"
    font2_obj = obj_num

    header = b"%PDF-1.4\n"
    offsets = []
    for i in range(1, obj_num + 1):
        if i in objs:
            offsets.append((i, len(header)))
            header += objs[i].encode("latin-1", errors="replace")

    xref_pos = len(header)
    xref = f"xref\n0 {obj_num + 1}\n"
    xref += "0000000000 65535 f \n"
    for i in range(1, obj_num + 1):
        off = next((o for num, o in offsets if num == i), 0)
        xref += f"{off:010d} 00000 n \n"
    header += xref.encode("latin-1")

    trailer = f"trailer\n<< /Size {obj_num + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
    header += trailer.encode("latin-1")

    return header

FORMATS = {
    "html": {"ext": ".html", "gen": generate_html, "desc": "HTML Report"},
    "json": {"ext": ".json", "gen": generate_json, "desc": "JSON Data"},
    "csv":  {"ext": ".csv",  "gen": generate_csv,  "desc": "CSV Spreadsheet"},
    "pdf":  {"ext": ".pdf",  "gen": generate_pdf,  "desc": "PDF Report"},
    "ps1":  {"ext": ".ps1",  "gen": generate_ps1,  "desc": "PowerShell Remediation Script"},
}

def save_report(checks, fmt="html", filepath=None):
    if fmt not in FORMATS:
        raise ValueError(f"Unknown format: {fmt}. Use one of: {', '.join(FORMATS)}")
    fmt_info = FORMATS[fmt]
    content = fmt_info["gen"](checks)
    if filepath is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(REPORT_DIR, f"CISO_Audit_Report_{ts}{fmt_info['ext']}")
    if isinstance(content, bytes):
        with open(filepath, "wb") as f:
            f.write(content)
    else:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
    return filepath
