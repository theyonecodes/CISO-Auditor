# Project Plan — CISO Security Auditor

## Who This Is For

| Persona | What they need | How often they use it |
|---------|---------------|----------------------|
| Freelance IT consultant | Quick audit + report for clients | Weekly per client |
| Small business owner | "Am I secure?" + proof for auditor/insurer | Monthly/quarterly |
| Homelab hobbyist | Score going up over time | Weekly |
| IT helpdesk | Green/red light before deploying machine | Per machine |

## The Loop We're Building

1. Run it → get a score
2. Fix some things
3. Run it again → see score improve
4. Show the improved report to someone
5. Feel good → tell someone else

---

## Phase 0: Prototype (Sprint 0 — DONE)

- Core check loop with 30 sample checks
- Basic console output
- **Deliverable:** Proof that registry + PS scanning works

## Phase 1: Engine (Sprints 1-2 — DONE)

- All 100 checks implemented
- All 100 remediation texts
- 15 auto-fix methods
- Registry backup + System Restore + undo
- **Deliverable:** `auditor_core.py` — fully functional engine

## Phase 2: GUI (Sprint 2-3 — DONE)

- Tkinter window with all sections
- Dark theme styling
- Treeview + detail pane interaction
- Export to HTML/JSON/CSV
- Responsive layout + visible scrollbars
- **Deliverable:** `main.py` + `export_report.py` — usable desktop app

## Phase 3: Safety & Polish (Sprint 4 — DONE)

- Admin check + confirmation dialogs
- Alternating row colors
- Better contrast / modern palette
- Full documentation (PDR, arch, backlog, roadmap)
- GitHub repository
- **Deliverable:** Production-ready v1.0

## Phase 4: Polish & Extensions (Sprint 5 — DONE)

- Treeview search/filter bar
- Category collapse/expand toggles
- Right-click context menu
- Per-check undo
- PDF export (pure-Python)
- PowerShell remediation script export
- Persistent settings
- Casual language throughout
- **Deliverable:** Feature-complete v1.1

## Phase 5: Make It Sticky (Sprint 6 — CURRENT)

- PyInstaller .exe bundle (no Python needed)
- Scan history storage (save every scan)
- Score trend tracking (before/after comparison)
- Casual language in reports
- **Deliverable:** v1.2 release — reason to run it twice

## Phase 6: Make It Useful for Consultants (Sprint 7 — NEXT)

- Multi-machine mode (scan 10 machines, see all scores)
- Better PDF reports (professional-looking)
- CLI mode (scriptable for RMM tools)
- Report comparison (machine A vs machine B)
- **Deliverable:** v1.3 release — useful for client work

---

## Milestone Schedule

| Milestone | Date | What |
|-----------|------|------|
| M1: Engine | 2026-06-05 | 100 checks + 15 fixes |
| M2: GUI | 2026-06-07 | Dark theme + export |
| M3: Safety | 2026-06-09 | Restore point + undo + admin check |
| M4: v1.0 | 2026-06-14 | GitHub repo + docs |
| M5: v1.1 | 2026-06-28 | Search + toggles + PDF + PS1 |
| M6: v1.2 | 2026-07-26 | .exe + scan history + trend |
| M7: v1.3 | 2026-08-16 | Multi-machine + CLI + better reports |

---

## How We Decide What to Build

We don't build features because they're cool. We build them because they answer one of these questions:

1. **Can someone without Python use this?** → .exe
2. **Is there a reason to run it twice?** → scan history + trend
3. **Can a consultant show this to a client?** → better reports
4. **Does it talk like a human?** → casual language

If a feature doesn't answer one of these, it doesn't ship.
