# CISO Advanced Security Auditor

> 100-point automated Windows security audit — offline, zero dependencies, one-click fixes.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)
![Status](https://img.shields.io/badge/status-v1.1-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![Dependencies](https://img.shields.io/badge/dependencies-zero-success)

---

## Quick Start

```batch
python main.py
```

No pip install. No setup. Works on any Windows machine with Python 3.8+.

## What It Does

Scans a Windows 10/11 endpoint against **100 CISO-level security checks**
across 8 domains, shows step-by-step remediation for every finding, and
applies **one-click auto-fixes** for 15 common misconfigurations.

All changes are **reversible** — registry backup, System Restore Point, and
full UNDO capability included.

## Features

- 100 security checks across 8 audit domains
- 100 remediation texts with step-by-step instructions
- 15 one-click auto-fixes (UAC, SMBv1, LSA, Defender, ASR, etc.)
- Dark theme (GitHub-dark palette, WCAG AAA contrast)
- Live progress bar + summary stats + security score
- Treeview search/filter bar — type to find any check instantly
- Category toggle bar — collapse/expand domain groups
- Right-click context menu — view details, apply fix, undo, copy
- Per-check undo — revert single fixes without affecting others
- Export: HTML (JS search/filter), JSON (SIEM), CSV, PDF, PowerShell
- System Restore Point before every fix
- Registry backup with full rollback
- UNDO ALL — revert every change in one click
- Admin check + confirmation dialogs
- Persistent settings (remembers export format)
- Launches maximized, responsive layout
- Zero pip dependencies — pure Python stdlib

## Screenshot

```
┌──────────────────────────────────────────────────────────────┐
│  CISO WINDOWS SECURITY AUDITOR                  SCORE: 30%   │
├──────────────────────────────────────────────────────────────┤
│ [RUN DEEP SCAN] 🔍 Search... [EXPORT] HTML JSON CSV PDF PS1  │
│  [FIX ALL] [UNDO]  ████████░░░░  Scanning [42/100]...       │
├──────────────────────────────────────────────────────────────┤
│ ▾ Boot  ▾ OS  ▾ Persistence  ▾ Identity  ▾ Network  ...    │
├──────────────────────────────────────────────────────────────┤
│  PASS: 30  |  FAIL: 22  |  WARN: 48  |  PEND: 0             │
├──────────────────────────────────────────────────────────────┤
│  #042  UAC Prompts                            [ FAIL ]       │
│  Details: UAC is DISABLED.                                   │
│  Remediation: Enable UAC via registry...                     │
│  [APPLY AUTO-FIX] [UNDO FIX]                                 │
└──────────────────────────────────────────────────────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `main.py` | Tkinter GUI — window, toolbar, search, treeview, detail pane, context menu |
| `auditor_core.py` | Engine — 100 checks, 15 fixes, registry backup, restore point, undo |
| `export_report.py` | Report generation — HTML, JSON, CSV, PDF, PowerShell |

## Audit Domains

| # | Domain | Checks | Auto-Fixable |
|---|--------|--------|-------------|
| 1 | Boot, Firmware & Hardware | 1-10 | — |
| 2 | OS-Level Exploit Mitigations | 11-20 | LSA Protection |
| 3 | Deep Persistence Mechanisms | 21-40 | — |
| 4 | Identity & Access Management | 41-50 | UAC, NTLM, SMB Signing |
| 5 | Network, Firewall & Traffic | 51-65 | SMBv1 |
| 6 | Process Execution & App Whitelisting | 66-75 | PS EP, PS Logging |
| 7 | File System & Data Security | 76-85 | Clipboard History |
| 8 | Auditing, Logging & Telemetry | 86-100 | CmdLine, Telemetry, Defender, ASR, CFA, NetProtection |

## Safety

Every change is reversible:

1. **System Restore Point** — created before each fix
2. **Registry Backup** — original value saved before overwrite
3. **UNDO ALL** — click UNDO to restore every changed key
4. **Per-Check Undo** — revert single fixes individually
5. **Admin Check** — blocks changes if not running as Administrator
6. **Confirmation** — shows full change list before applying

## Export Formats

| Format | Description |
|--------|-------------|
| HTML | Interactive report with JS search, filter by status/domain |
| JSON | SIEM-ready structured data |
| CSV | Spreadsheet compatible |
| PDF | Multi-page printable report (pure Python, no deps) |
| PowerShell | Remediation script with all manual fix steps |

## Requirements

- Windows 10 or 11 (x64)
- Python 3.8+ (any build)
- Administrator privileges (for fixes only; scanning works without)

## Roadmap

- Headless CLI mode · Scheduled scans · Trend tracking
- Custom check plug-in system · CIS/NIST mapping · SIEM integration

See [docs/ROADMAP.md](docs/ROADMAP.md) for full timeline.

## Documentation

| Doc | Description |
|-----|-------------|
| [PDR.md](docs/PDR.md) | Product Design Requirements |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture |
| [TECH_STACK.md](docs/TECH_STACK.md) | Technology choices |
| [DESIGN.md](docs/DESIGN.md) | UI/UX design |
| [ROADMAP.md](docs/ROADMAP.md) | Release roadmap |
| [PROJECT_PLAN.md](docs/PROJECT_PLAN.md) | Milestones & timeline |
| [SECURITY.md](docs/SECURITY.md) | Security & safety |
