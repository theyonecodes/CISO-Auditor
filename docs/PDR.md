# Product Design Requirements — CISO Security Auditor

## 1. What This Is

A script that checks if your Windows machine is secure. Gives you a score. Tells you what's broken. Fixes some of it.

## 2. Who Uses This

| Persona | What they need | How often |
|---------|---------------|-----------|
| Freelance IT consultant | Quick audit + report for clients | Weekly per client |
| Small business owner | "Am I secure?" + proof for auditor/insurer | Monthly/quarterly |
| Homelab hobbyist | Score going up over time | Weekly |
| IT helpdesk | Green/red light before deploying machine | Per machine |

**Who doesn't use this:**
- Enterprise security teams (they have Nessus, CrowdStrike)
- Anyone without Python (unless we make an .exe)
- Anyone who needs daily monitoring

## 3. The Problem

Small businesses and freelancers need to know if their machines are secure. They don't have $10K/year for enterprise tools. They need a quick answer and a report they can show someone.

## 4. The Retention Problem

Right now, someone runs the tool once, gets a score, maybe fixes a few things, and never opens it again. That's not useful. We need a reason for people to come back.

**The loop we're building:**
1. Run it → get a score
2. Fix some things
3. Run it again → see score improve
4. Show the improved report to someone
5. Feel good → tell someone else

## 5. What It Does

### Scanning
- Runs 100 security checks across 8 domains
- Returns PASS / FAIL / WARNING / PENDING per check
- Shows live progress during scan
- Gives an overall score (0-100%)

### Fixing
- 15 checks can be auto-fixed with one click
- Creates a System Restore Point before fixing
- Backs up every registry key before changing it
- UNDO button reverts everything
- Won't let you fix without admin rights

### Reporting
- HTML report with search and filtering
- JSON export for SIEM integration
- CSV for spreadsheets
- PDF for printing
- PowerShell script with manual fix steps

## 6. What It Doesn't Do

- Not antivirus
- Not a background monitor
- Doesn't fix everything (85 of 100 checks need manual work)
- Doesn't make your machine secure — just tells you what's wrong

## 7. Requirements

### Must Work
- Windows 10/11 x64
- Python 3.8+ with zero pip dependencies
- Scan completes in under 60 seconds
- All fixes reversible
- Admin only for fixes, not scanning

### Must Feel
- Casual language — no corporate speak
- Dark theme that doesn't burn your eyes
- Responsive — works maximized or tiled
- Fast — doesn't freeze during scan

## 8. How We Decide

We don't build features because they're cool. We build them because they answer one of these questions:

1. Can someone without Python use this?
2. Is there a reason to run it twice?
3. Can a consultant show this to a client?
4. Does it talk like a human?

If a feature doesn't answer one of these, it doesn't ship.
