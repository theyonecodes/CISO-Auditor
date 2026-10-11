# CISO Security Auditor

Checks if your Windows machine is secure. Tells you what's broken. Fixes some of it.

## Who is this for?

- **Freelance IT consultants** — you set up machines for clients, you need to show "it's secure"
- **Small business owners** — you have 5-50 machines, no IT dept, you need to prove security to your insurer or auditor
- **Homelab hobbyists** — you run Windows VMs, you want to harden them and see your score improve
- **IT helpdesk** — you get a machine, you need a quick green/red light before deploying it

If you have a big security team with Nessus and CrowdStrike, this isn't for you. This is for people who need a quick answer without spending $10K/year on enterprise tools.

## What it does

Runs 100 security checks and gives you a score out of 100%. That's it.

```
python main.py
```

No install. No config. Just run it.

## What you get

- A score: "Your machine is 30% secure"
- A list of what's broken and how to fix it
- 15 things fixed automatically with one click
- A report you can show your boss, client, or auditor

## What it doesn't do

- It's not antivirus
- It doesn't monitor anything in the background
- It doesn't fix everything (85 of 100 checks need manual work)
- It won't make your machine secure — it just tells you what's wrong

## The loop that makes this useful

1. Run it → get a score
2. Fix some things
3. Run it again → see score improve
4. Show the improved report to someone
5. Feel good

## 🆕 New in v1.2 — Toolkit Integration

| Feature | Description |
|---------|-------------|
| **🛡️ Shared BackupEngine** | Now uses `theyonecodes/toolkit` BackupEngine — automatic registry/file backups with SHA-256 manifest + rollback |
| **🤖 Jev Router Triage** | AI model routing with Choice/Score/Noul primitives — confidence scoring for fixes, guardrails, human review triggers |
| **🎨 Shared DarkTheme** | Uses `theyonecodes/toolkit` DarkTheme (consistent with Windows-Super-Smooth, electron-gpu-crash-fix, pkgdrop, universal-browser-backup) |
| **📊 Scan History Database** | SQLite database for scan history, trend tracking, and score trends |
| **🤖 Jev Router Triage** | AI triage for security fixes — confidence scoring, guardrails, human review triggers |

---

## Features

- 100 security checks across 8 domains
- Dark theme (doesn't burn your eyes) — now from `theyonecodes/toolkit` DarkTheme
- Search bar to find checks fast
- Collapse/expand categories
- Right-click menu (copy, fix, undo)
- Export: HTML, JSON, CSV, PDF, PowerShell script
- Undo everything if you mess up
- Zero dependencies — just Python
- **🛡️ Shared BackupEngine** — Pre-fix registry snapshots with SHA-256 manifest + auto-rollback
- **🤖 Jev Router Triage** — AI triage for security fixes, confidence scoring, guardrails
- **📊 Scan History Database** — SQLite database for scan history, trend tracking, score trends

---

## Safety

Every fix is reversible:

1. Creates a System Restore Point before touching anything
2. Backs up every registry key it changes (now via shared BackupEngine with SHA-256 manifest)
3. UNDO button reverts everything
4. Won't let you fix things without admin rights
5. Asks "are you sure?" before every fix

## Requirements

- Windows 10 or 11
- Python 3.8+
- Admin rights (only for fixes — scanning works without)

## What's in the box

| File | What it does |
|------|-------------|
| `main.py` | The app — runs the scan, shows results (now with toolkit integration) |
| `auditor_core.py` | The engine — 100 checks, 15 fixes (legacy, migrating to toolkit) |
| `export_report.py` | Makes reports (HTML, JSON, CSV, PDF, PS1) |
| `vendor/toolkit/` | Git submodule — shared engines (BackupEngine, DarkTheme, AuditEngine, FixEngine, JevRouter) |

## What it checks

| # | Category | Auto-fix? |
|---|----------|-----------|
| 1-10 | Boot & Firmware (Secure Boot, TPM, BitLocker) | No |
| 11-20 | OS Exploit Protections (ASLR, DEP, CFG, LSA) | LSA |
| 21-40 | Persistence (Scheduled Tasks, Registry, Services) | No |
| 41-50 | Identity (UAC, NTLM, SMB Signing, Passwords) | UAC, NTLM, SMB |
| 51-65 | Network (Firewall, DNS, NetBIOS, SMBv1) | SMBv1 |
| 66-75 | Execution (PowerShell, AppLocker, SmartScreen) | PS Policy, Logging |
| 76-85 | Files (NTFS, Shadow Copies, Memory Dumps) | Clipboard |
| 86-100 | Logging (Audit Policy, Defender, ASR, CFA) | CmdLine, Telemetry, Defender |

## 🆕 Toolkit Integration (v1.2)

### 🛡️ Shared BackupEngine

The core backup/restore engine now lives in `theyonecodes/toolkit` and provides:

| Feature | Description |
|---------|-------------|
| **Automatic backups** | Before any registry/file/BCD/EFI change |
| **SHA-256 manifest** | Every backed-up item has a hash |
| **Automatic rollback** | On failure, restores from backup |
| **Cross-platform** | Python + PowerShell implementations |
| **Reusable** | Used by Windows-Super-Smooth, electron-gpu-crash-fix, pkgdrop, universal-browser-backup |

```python
# Python usage (from toolkit)
from toolkit.backup_engine import invoke_with_backup

result = invoke_with_backup(
    tool_name="CISO-Auditor",
    description="Enable LSA Protection",
    action=lambda: enable_lsa_protection(),
    registry_keys=[r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"],
    backup_bcd=True
)
```

### 🤖 Jev Router Triage

AI model routing with Choice/Score/Noul primitives for security fix decisions:

| Primitive | Purpose |
|-----------|---------|
| **Choice** | Select model for task (local vs cloud, aggressive vs safe fixes) |
| **Score** | Confidence 0-100% based on capability match, cost, latency |
| **Noul** | Guardrails: if confidence < 70% → human review; if sensitive → human review |

**GUI Integration:**
- **Post-scan** → Jev triage for all auto-fixable findings
- **Per-fix** → Jev triage button for confidence scoring
- **Guardrails** → Human review required for sensitive operations

**CLI Usage:**
```cmd
python vendor\toolkit\jev-router\jev_router.py --choice system_optimization --context "{\"task_type\":\"security_fix_triage\",\"sensitive\":true,\"findings\":[{\"id\":20,\"name\":\"LSA Protection\"}]}"
```

### 📊 Scan History Database

SQLite database (`scan_history.db`) stores:
- Timestamp, score, passed/failed/warning/pending counts
- Full scan details for trend analysis
- Up to 100 scans retained

### 🎨 Shared DarkTheme

Uses `theyonecodes/toolkit` DarkTheme — consistent with:
- Windows-Super-Smooth
- electron-gpu-crash-fix
- pkgdrop
- universal-browser-backup

---

## What's in the box

| File | What it does |
|------|-------------|
| `main.py` | The app — runs the scan, shows results (now with toolkit integration) |
| `auditor_core.py` | The engine — 100 checks, 15 fixes (legacy, migrating to toolkit) |
| `export_report.py` | Makes reports (HTML, JSON, CSV, PDF, PS1) |
| `vendor/toolkit/` | Git submodule — shared engines (BackupEngine, DarkTheme, AuditEngine, FixEngine, JevRouter) |

## What it checks

| # | Category | Auto-fix? |
|---|----------|-----------|
| 1-10 | Boot & Firmware (Secure Boot, TPM, BitLocker) | No |
| 11-20 | OS Exploit Protections (ASLR, DEP, CFG, LSA) | LSA |
| 21-40 | Persistence (Scheduled Tasks, Registry, Services) | No |
| 41-50 | Identity (UAC, NTLM, SMB Signing, Passwords) | UAC, NTLM, SMB |
| 51-65 | Network (Firewall, DNS, NetBIOS, SMBv1) | SMBv1 |
| 66-75 | Execution (PowerShell, AppLocker, SmartScreen) | PS Policy, Logging |
| 76-85 | Files (NTFS, Shadow Copies, Memory Dumps) | Clipboard |
| 86-100 | Logging (Audit Policy, Defender, ASR, CFA) | CmdLine, Telemetry, Defender |

## What's coming next

| Version | What | Why |
|---------|------|-----|
| v1.3 | .exe bundle + scan history UI + score trend charts | So people without Python can use it, and there's a reason to run it again |
| v1.4 | Multi-machine mode + better PDF reports | So consultants can scan 10 machines and show professional reports |
| v2.0 | Scheduled scans + email alerts + CIS mapping | So it runs automatically and tells you when things change |

See [docs/ROADMAP.md](docs/ROADMAP.md) for details.

---

## Safety

Every fix is reversible:

1. Creates a System Restore Point before touching anything
2. Backs up every registry key it changes (now via shared BackupEngine with SHA-256 manifest)
3. UNDO button reverts everything
4. Won't let you fix things without admin rights
5. Asks "are you sure?" before every fix

## Requirements

- Windows 10 or 11
- Python 3.8+
- Admin rights (only for fixes — scanning works without)

## Docs

| Doc | What it is |
|-----|-----------|
| [PDR.md](docs/PDR.md) | What we're building and why |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the code is structured |
| [TECH_STACK.md](docs/TECH_STACK.md) | Why we chose what we chose |
| [DESIGN.md](docs/DESIGN.md) | UI/UX decisions |
| [ROADMAP.md](docs/ROADMAP.md) | What's coming next |
| [PROJECT_PLAN.md](docs/PROJECT_PLAN.md) | Timeline and milestones |
| [SECURITY.md](docs/SECURITY.md) | Safety and reversibility |

---

## License

MIT License - see [LICENSE](LICENSE)