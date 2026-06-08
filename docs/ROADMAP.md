# Roadmap — CISO Advanced Security Auditor

## Legend
- 🟢 **Done** — shipped and verified
- 🟡 **In Progress** — being worked on this sprint
- ⬜ **Planned** — estimated for future sprint
- 📅 **Target** — release date

---

## v1.0 — "Baseline" (Current 🟢)

**Target**: 2026-06-14 | **Status**: 66% complete

### Scan Engine (100%)
- [x] 100 checks across 8 domains
- [x] 100 remediation texts
- [x] Live progress reporting

### Auto-Fix (100%)
- [x] 15 one-click fixes
- [x] Registry backup + System Restore
- [x] UNDO ALL rollback
- [x] Admin check + confirmation dialogs

### GUI (100%)
- [x] Dark theme (GitHub palette)
- [x] Treeview + detail pane split
- [x] Progress bar + summary bar
- [x] Responsive resize + visible scrollbars

### Export (62%)
- [x] HTML (with JS search/filter)
- [x] JSON (SIEM-ready)
- [x] CSV
- [ ] PDF
- [ ] Remediation script export

---

## v1.1 — "Polished" (Next Sprint)

**Target**: 2026-06-28 | **Estimated**: 34 SP

| Feature | SP | Priority |
|---------|-----|----------|
| PDF export (libre → reportlab or WebView2) | 13 | P2 |
| Treeview search/filter bar | 5 | P2 |
| Collapsible category groups | 8 | P2 |
| Persistent settings (JSON config file) | 3 | P2 |
| Right-click context menu | 3 | P2 |
| Per-check undo | 5 | P2 |

---

## v1.2 — "Power User" (Mid-term)

**Target**: 2026-07-26 | **Estimated**: 34 SP

| Feature | SP | Priority |
|---------|-----|----------|
| Headless CLI mode (`--scan`, `--export`) | 8 | P2 |
| Scheduled scan via Task Scheduler | 5 | P2 |
| Remediation script export (.ps1) | 5 | P2 |
| Comparative scoring (trend graph) | 8 | P2 |
| PyInstaller .exe bundle | 5 | P2 |
| Email report delivery (SMTP) | 8 | P2 |

---

## v2.0 — "Enterprise" (Long-term)

**Target**: 2026-Q3 | **Estimated**: 81 SP

| Feature | SP | Priority |
|---------|-----|----------|
| Custom check plug-in system | 13 | P3 |
| CIS / NIST / ISO framework mapping | 21 | P3 |
| SIEM integration (Syslog / WEF) | 13 | P3 |
| CVE database lookup | 13 | P3 |
| Remote scan (WinRM) | 21 | P3 |
| Light theme toggle | 8 | P3 |
| Multi-language (i18n) | 13 | P3 |

---

## Milestone Timeline

```
Jun 2026                Jul 2026                Aug 2026
│                       │                       │
v1.0────●──────────────│                       │
        │  Sprint 4     │                       │
        │  (safety,     │                       │
        │   docs, repo) │                       │
                       v1.1───●────────────────│
                              │  Sprint 5-6     │
                              │  (PDF, search,  │
                              │   settings)     │
                                               v2.0───●───────▶
                                                      │  Sprint 7-10
                                                      │  (plugins, CIS,
                                                      │   SIEM, remote)
```
