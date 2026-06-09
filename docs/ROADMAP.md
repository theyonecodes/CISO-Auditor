# Roadmap — CISO Security Auditor

## The Problem We're Solving

Small businesses, freelancers, and homelab users need to know if their Windows machines are secure. They don't have $10K/year for Nessus or CrowdStrike. They need a quick answer and a report they can show someone.

## The Retention Problem

Right now, someone runs the tool once, gets a score, maybe fixes a few things, and never opens it again. That's not useful. We need a reason for people to come back.

**The loop we're building:**
1. Run it → get a score
2. Fix some things
3. Run it again → see score improve
4. Show the improved report to someone
5. Feel good → tell someone else

---

## v1.0 — "Baseline" (Done)

- 100 checks, 15 auto-fixes, dark GUI
- Export: HTML, JSON, CSV
- Registry backup + System Restore + UNDO

## v1.1 — "Polished" (Done)

- Search bar, category toggles, context menu
- Per-check undo, PDF export, PS1 export
- Persistent settings, maximized launch

---

## v1.2 — "Sticky" (Current)

**Goal:** Give people a reason to run it twice.

| Feature | What it does | Why it matters | SP |
|---------|-------------|----------------|-----|
| **PyInstaller .exe** | Double-click to run, no Python needed | 90% of users don't have Python | 5 |
| **Scan history** | Save every scan to a JSON file with timestamp | Without this, there's no "before and after" | 8 |
| **Score trend** | "Last time: 30%, Now: 65%" | This is the hook — people want to see improvement | 5 |
| **Casual language** | UI and reports speak like a human, not a corporation | People trust things that talk like them | 3 |

**Target:** 2026-07-26

---

## v1.3 — "Consultant" (Next)

**Goal:** Make it useful for people who set up machines for clients.

| Feature | What it does | Why it matters | SP |
|---------|-------------|----------------|-----|
| **Multi-machine mode** | Scan 10 machines, see all scores in one place | Consultants need to audit fleets, not single machines | 13 |
| **Better PDF reports** | Professional-looking reports with logos and summaries | The report IS the product — make it look like it | 8 |
| **CLI mode** | `python main.py --scan --export json` | Scriptable for RMM tools and automation | 8 |
| **Report comparison** | "Machine A: 45%, Machine B: 72%" | Show clients which machines need work | 5 |

**Target:** 2026-08-16

---

## Timeline

```
Jun 2026          Jul 2026          Aug 2026
│                 │                 │
v1.0 ──●         │                 │
v1.1 ────●       │                 │
        │         v1.2 ──────●     │
        │         (sticky)         │
        │                          v1.3 ──────●
        │                          (consultant)
```

---

## How We Prioritize

We don't build features because they're cool. We build them because they answer one of these questions:

1. **Can someone without Python use this?** → .exe
2. **Is there a reason to run it twice?** → scan history + trend
3. **Can a consultant show this to a client?** → better reports
4. **Does it talk like a human?** → casual language

If a feature doesn't answer one of these, it doesn't ship.
