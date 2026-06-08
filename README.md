# CISO Advanced Security Auditor

> 100-point automated Windows security audit — offline, zero dependencies, one-click fixes.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)
![Status](https://img.shields.io/badge/status-v1.0--beta-green)
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

✅ 100 security checks (8 domains)  
✅ 100 remediation texts  
✅ 15 one-click auto-fixes (UAC, SMBv1, LSA, Defender, etc.)  
✅ Dark theme (GitHub-dark palette)  
✅ Live progress + summary stats  
✅ Export: HTML (with JS search/filter), JSON (SIEM), CSV  
✅ Registry backup + System Restore + UNDO ALL  
✅ Admin check + confirmation dialogs  
✅ Responsive layout — works maximized or tiled  
✅ Zero pip dependencies — Python stdlib only  

## Screenshot

```
┌──────────────────────────────────────────────────────┐
│  CISO WINDOWS SECURITY AUDITOR      SCORE: 30%       │
├──────────────────────────────────────────────────────┤
│ [RUN DEEP SCAN] [EXPORT] | Format: ○HTML ○JSON ○CSV  │
│  [FIX ALL] [UNDO]  ████████░░  Scanning [42/100]... │
├──────────────────────────────────────────────────────┤
│  PASS: 30  |  FAIL: 22  |  WARN: 48  |  PEND: 0     │
├──────────────────────────────────────────────────────┤
│  #042 UAC Prompts                        [ FAIL ]    │
│  Details: UAC is DISABLED.                           │
│  Remediation: ⚡ Enable UAC via registry...           │
│  [APPLY AUTO-FIX]                                     │
└──────────────────────────────────────────────────────┘
```

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `main.py` | ~566 | Tkinter GUI — window, toolbar, treeview, detail pane |
| `auditor_core.py` | ~1560 | Engine — 100 checks, 15 fixes, remediation, backup/undo |
| `export_report.py` | ~230 | Report generation — HTML, JSON, CSV |

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
4. **Admin Check** — blocks changes if not running as Administrator
5. **Confirmation** — shows full change list before applying

## Requirements

- Windows 10 or 11 (x64)
- Python 3.8+ (any build)
- Administrator privileges (for fixes only; scanning works without)

## Roadmap

- PDF export · Search/filter bar · Persistent settings
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
