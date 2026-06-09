# Architecture — CISO Security Auditor

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        main.py                               │
│  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Header   │  │ Toolbar  │  │ Summary  │  │  Main    │  │
│  │  (score,  │  │ (scan,   │  │ (PASS/   │  │ Content  │  │
│  │   title)  │  │  export, │  │ FAIL/    │  │ ┌──────┐ │  │
│  │           │  │  fix,    │  │ WARN/    │  │ │Tree  │ │  │
│  │           │  │  undo,   │  │ PENDING) │  │ │View  │ │  │
│  │           │  │  prog)   │  │          │  │ ├──────┤ │  │
│  │           │  │          │  │          │  │ │Detail│ │  │
│  │           │  │          │  │          │  │ │Pane  │ │  │
│  └───────────┘  └──────────┘  └──────────┘  │ └──────┘ │  │
│                                              └──────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │ imports / calls
          ┌────────────┼────────────┐
          ▼            ▼            ▼
┌─────────────────┐ ┌─────────────────────┐ ┌──────────────┐
│  auditor_core.py │ │   export_report.py  │ │ Python stdlib │
│  ┌─────────────┐ │ │  ┌───────────────┐  │ │ ┌──────────┐ │
│  │ SecurityCheck│ │ │  │ generate_html │  │ │ │ winreg   │ │
│  │  (data class)│ │ │  │ generate_json │  │ │ │ ctypes   │ │
│  ├─────────────┤ │ │  │ generate_csv  │  │ │ │ threading│ │
│  │ AuditorCore  │ │ │  │ save_report   │  │ │ │ os       │ │
│  │ ┌─────────┐ │ │ │  └───────────────┘  │ │ │ subpro.. │ │
│  │ │100 check│ │ │ └─────────────────────┘ │ └──────────┘ │
│  │ │methods  │ │ │                         └──────────────┘
│  │ │15 fix   │ │ │
│  │ │methods  │ │ │
│  │ │remediat.│ │ │
│  │ │backups  │ │ │
│  │ └─────────┘ │ │
│  └─────────────┘ │
└─────────────────┘
```

## Module Relationships

### main.py (UI Layer)
- **Purpose**: Tkinter window, user interaction, event handling
- **Depends on**: `auditor_core.py`, `export_report.py`
- **Threads**: 1 background thread per scan or fix operation
- **State**: `auditor` (AuditorCore instance), `selected_check`, `scan_complete`

### auditor_core.py (Engine Layer)
- **Purpose**: All 100 check implementations, 15 fix methods, remediation DB,
  registry backup/restore
- **Depends on**: `winreg`, `ctypes`, `subprocess`, `os` (stdlib only)
- **State**: `checks` (list of SecurityCheck), `_registry_backups`,
  `fix_history`

### export_report.py (Export Layer)
- **Purpose**: Serialize check results to HTML/JSON/CSV
- **Depends on**: `json`, `csv`, `io`, `os`, `datetime` (stdlib only)
- **Stateless**: Pure functions — takes list of checks, returns file path

## Data Flow: Scan

```
User clicks RUN SCAN
        │
        ▼
main.py: run_scan_thread()
        │ starts background thread
        ▼
main.py: _scan_process()
        │ calls
        ▼
auditor_core.py: run_all_checks(progress_callback)
        │
        ▼ (for each of 100 checks)
auditor_core.py: _execute_check(check)
        │ dispatch → self._check_NNN(check)
        ▼
Check runs: reg read / PS cmd / file check
        │
        ▼
check.status + check.details updated
        │ callback fires
        ▼
main.py: _update_progress() → treeview + progress bar + status
```

## Data Flow: Fix

```
User clicks FIX THIS or FIX ALL
        │
        ▼
main.py: confirmation dialog + admin check
        │
        ▼
auditor_core.py: fix_check(check)
        │ 1. Create System Restore Point (PS)
        │ 2. dispatch → self._fix_NNN(check)
        │ 3. Each _reg_write_safe() backs up original value
        ▼
check.status updated to PASS
fix_history.append((check.id, desc))
        │
        ▼
main.py: treeview + summary + undo button enabled
```

## Thread Safety

- Only **one** background thread at a time (scan XOR fix)
- All UI updates marshalled via `root.after(0, callback)`
- AuditorCore has no mutable shared state between threads
- Registry backups are per-instance, not shared

## File Layout

```
CISO_Auditor/
├── main.py                  # GUI entry point
├── auditor_core.py          # Engine: checks, fixes, backup
├── export_report.py         # HTML/JSON/CSV/PDF/PS1 export
├── docs/
│   ├── PDR.md
│   ├── ARCHITECTURE.md
│   ├── TECH_STACK.md
│   ├── DESIGN.md
│   ├── ROADMAP.md
│   ├── PROJECT_PLAN.md
│   ├── SECURITY.md
│   └── README.md
└── *.csv / *.html / *.json / *.pdf / *.ps1  # generated reports
```
