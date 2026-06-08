# Product Design Requirements — CISO Advanced Security Auditor

## 1. Product Overview

A standalone Windows desktop application that automates 100 CISO-level security
checks, provides step-by-step remediation, and applies one-click auto-fixes for
common misconfigurations. Designed for security engineers, sysadmins, and
consultants who need a rapid, offline assessment of a Windows 10/11 endpoint.

## 2. Goals & Objectives

| # | Goal | Measure |
|---|------|---------|
| G1 | Automate 100-point CISO audit in < 60s | Scan completes in 30-45s |
| G2 | Provide actionable remediation for every fail | 100/100 checks have remediation text |
| G3 | Fix common misconfigurations with one click | 15 registry/PS fixes |
| G4 | Export findings in SIEM-ready formats | HTML, JSON, CSV |
| G5 | Zero cost, no dependencies beyond Python + OS | Single `python main.py` to run |
| G6 | Safe — every change is reversible | Registry backup + System Restore + confirmation dialogs |

## 3. Target Users

- **Security consultants** — rapid pre-audit before deploying EDR/formal tools
- **Sysadmins** — baseline endpoint hardening before domain join
- **CISOs / security managers** — report-ready HTML export with domain-level scoring
- **IT support** — one-click fix for common issues (UAC, SMBv1, telemetry)

## 4. Functional Requirements

### FR-1: Security Scanning

- [x] FR-1.1 Execute all 100 checks sequentially
- [x] FR-1.2 Support 8 audit domains (Boot, OS Mitigations, Persistence, IAM,
       Network, Execution, File System, Logging)
- [x] FR-1.3 Return PASS / FAIL / WARNING / PENDING per check
- [x] FR-1.4 Show live progress during scan (progress bar + per-check status)
- [x] FR-1.5 Threaded execution — UI remains responsive during scan

### FR-2: Remediation

- [x] FR-2.1 Display step-by-step remediation text for every check
- [x] FR-2.2 Indicate which checks are auto-fixable (vs manual-only)
- [x] FR-2.3 Apply individual auto-fix on demand
- [x] FR-2.4 Apply batch auto-fix (FIX ALL)
- [ ] FR-2.5 Export remediation as PowerShell/.bat script

### FR-3: Safety & Undo

- [x] FR-3.1 Create System Restore Point before any fix
- [x] FR-3.2 Back up each registry key before modification
- [x] FR-3.3 Verify admin privileges before attempting fixes
- [x] FR-3.4 Show confirmation dialog with change list
- [x] FR-3.5 UNDO ALL — restore every changed key to original value
- [ ] FR-3.6 Per-check undo (revert single fix)

### FR-4: Reporting & Export

- [x] FR-4.1 Export to HTML with JS-based search, filter, and sort
- [x] FR-4.2 Export to JSON (SIEM-ready, structured)
- [x] FR-4.3 Export to CSV (spreadsheet-compatible)
- [ ] FR-4.4 Export to PDF
- [ ] FR-4.5 Email report with SMTP config

### FR-5: UI / UX

- [x] FR-5.1 Dark theme with GitHub-dark color palette
- [x] FR-5.2 Responsive layout — treeview and detail pane reflow on resize
- [x] FR-5.3 Alternating row colors for readability
- [x] FR-5.4 Visible scrollbar with hover highlight
- [x] FR-5.5 Color-coded status badges (PASS=green, FAIL=red, WARN=amber)
- [x] FR-5.6 Domain summary bar with live counts
- [x] FR-5.7 Overall security score displayed in header
- [ ] FR-5.8 Search/filter bar within treeview
- [ ] FR-5.9 Collapsible category group headers
- [ ] FR-5.10 Light theme toggle
- [ ] FR-5.11 Right-click context menu (copy, re-run check, etc.)

## 5. Non-Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-1 | Platform | Windows 10/11 x64 |
| NFR-2 | Runtime | Python 3.8+ with no pip dependencies |
| NFR-3 | Startup time | < 2s on modern hardware |
| NFR-4 | Scan time | < 60s for all 100 checks |
| NFR-5 | Memory | < 200 MB peak |
| NFR-6 | Security | All fixes reversible; restore point before modification |
| NFR-7 | Admin | Only fixes require admin; scan works without elevation |

## 6. User Stories

### MVP (v1.0 — DONE)
- As a sysadmin, I want to run 100 security checks with one click.
- As a consultant, I want to export a report my client can open in a browser.
- As an IT support tech, I want to fix UAC/SMBv1 without remembering regedit paths.
- As a security engineer, I want JSON output I can pipe into my SIEM.

### v1.1 (Planned)
- As a CISO, I want PDF reports with my company logo.
- As a sysadmin, I want to compare last week's score to today's.
- As an MSSP, I want to run the scanner from a command line / RMM tool.

### v2.0 (Planned)
- As a security architect, I want to write custom checks via a plug-in system.
- As a compliance officer, I want to map checks to CIS / NIST / ISO frameworks.
- As a SOC analyst, I want real-time log forwarding from the scan results.

## 7. Domain Coverage (8 of 8)

| # | Domain | Checks | Auto-Fix |
|---|--------|--------|----------|
| 1 | Boot, Firmware & Hardware | 1-10 | 0 |
| 2 | OS-Level Exploit Mitigations | 11-20 | 1 (LSA) |
| 3 | Deep Persistence Mechanisms | 21-40 | 0 |
| 4 | Identity & Access Management | 41-50 | 4 (UAC, NTLM, SMB, cached) |
| 5 | Network, Firewall & Traffic | 51-65 | 1 (SMBv1) |
| 6 | Process Execution & App Whitelisting | 66-75 | 2 (PS EP, PS logging) |
| 7 | File System & Data Security | 76-85 | 1 (Clipboard) |
| 8 | Auditing, Logging & Telemetry | 86-100 | 6 (cmdline, telemetry, Defender, ASR, CFA, NetProtect) |

## 8. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Tkinter over PyQt/Wx | Zero dependencies, pre-installed on every Windows Python |
| Threaded scan with `threading` | Tkinter is single-threaded; blocking `subprocess.run` must not freeze UI |
| `ctypes.windll` for admin check | Fast, no subprocess overhead |
| Per-value registry backup | Enables granular undo without full hive snapshots |
| GitHub-dark palette | Proven high-contrast dark scheme, developer-friendly |
