# Project Plan — CISO Advanced Security Auditor

## Phase Breakdown

### Phase 0: Prototype (Sprint 0 — COMPLETE)
- Core check loop with 30 sample checks
- Basic console output
- **Deliverable**: Proof that registry + PS scanning works

### Phase 1: Engine (Sprints 1-2 — COMPLETE)
- All 100 checks implemented
- All 100 remediation texts
- 15 auto-fix methods
- `run_all_checks()` with progress callback
- Registry backup + System Restore + undo
- **Deliverable**: `auditor_core.py` — fully functional engine

### Phase 2: GUI (Sprint 2-3 — COMPLETE)
- Tkinter window with all sections
- Dark theme styling
- Treeview + detail pane interaction
- Export to HTML/JSON/CSV
- Responsive layout + visible scrollbars
- **Deliverable**: `main.py` + `export_report.py` — usable desktop app

### Phase 3: Safety & Polish (Sprint 4 — CURRENT)
- Admin check + confirmation dialogs
- Alternating row colors
- Better contrast / modern palette
- Full documentation (PDR, arch, backlog, roadmap)
- GitHub repository
- **Deliverable**: Production-ready v1.0

### Phase 4: Extensions (Sprint 5+ — PLANNED)
- PDF export / search bar / collapsible groups
- CLI mode / scheduled scans
- Plug-in system / CIS mapping
- **Deliverable**: Enterprise-ready v2.0

---

## Milestone Schedule

| Milestone | Date | Deliverables |
|-----------|------|-------------|
| M1: Engine Complete | 2026-06-05 🟢 | `auditor_core.py` with 100 checks + 15 fixes |
| M2: GUI Complete | 2026-06-07 🟢 | `main.py` + `export_report.py` |
| M3: Safety Hardening | 2026-06-09 🟢 | Restore point, backup, undo, admin check |
| M4: v1.0 Release | 2026-06-14 🟡 | All docs + GitHub repo |
| M5: v1.1 Release | 2026-06-28 ⬜ | PDF export + search + collapsible groups |
| M6: v2.0 Release | 2026-Q3 ⬜ | Plug-ins + CIS mapping + SIEM + remote |

---

## Dependencies

| Task | Depends On |
|------|-----------|
| GUI development | AuditorCore with all check methods |
| Export features | Completed scan (checks have status + details) |
| Auto-fix | Registry write capability + admin check |
| Registry backup | `_reg_write_safe` wrapper around `_reg_write` |
| System Restore | PowerShell `Checkpoint-Computer` (admin) |
| Undo | Registry backup store |
| PDF export | Third-party library decision |
| Plug-in system | Stable check interface definition |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Registry access denied | High | Med | Admin check + clear error message |
| PS command fails on older Win10 | Med | Med | try/except around every PS call |
| Checkpoint-Computer disabled | Med | Low | Non-fatal — proceed with backup only |
| Tkinter theme broken on Win10 | Low | Med | Use `ttk.Style().theme_use("default")` |
| User runs without admin | High | High | Block fixes, allow scan only |
| Python not installed | Low | High | Document as requirement; offer PyInstaller |
