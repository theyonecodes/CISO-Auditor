# Security & Safety — CISO Advanced Security Auditor

## Design Philosophy

This tool makes system changes on behalf of the user. Every change is designed
to be **safe, reversible, and transparent**.

## What the Tool DOES

- **Reads** registry keys and runs PowerShell queries to check security state
- **Writes** registry keys to enable security features (UAC, LSA, SMB signing, etc.)
- **Runs PowerShell** to configure Windows features (DISM, Defender, auditpol)
- **Creates** System Restore Points before modification
- **Backs up** every registry value before changing it

## What the Tool DOES NOT Do

- Does NOT delete files or directories
- Does NOT install drivers or kernel modules
- Does NOT modify boot configuration (BCD)
- Does NOT disable security features (only enables them)
- Does NOT collect or transmit telemetry/user data
- Does NOT require network access (fully offline)
- Does NOT modify user data or documents

## Safety Mechanisms

### 1. Admin Privilege Check
- Every fix operation calls `is_admin()` via `ctypes.windll.shell32.IsUserAnAdmin()`
- If not admin: fix is blocked with a clear error message
- Scanning works WITHOUT admin privileges (read-only)

### 2. System Restore Point
- PowerShell `Checkpoint-Computer` is called before every fix
- Creates a system restore point with description "CISO Auditor Pre-Fix"
- Non-fatal if the System Restore service is disabled — registry backup still works

### 3. Registry Backup (`_reg_write_safe`)
- Before writing any registry value, the current value + type is read and stored
- Backups live in `_registry_backups` dict keyed by `(hive, subkey, name)`
- Backups persist for the lifetime of the AuditorCore instance

### 4. UNDO ALL Rollback
- Restores every backed-up registry key to its original value and type
- If there was no previous value, the key is deleted
- All checks are reset to PENDING state after undo

### 5. Confirmation Dialogs
- Single fix: `messagebox.askyesno("Confirm Fix", \...)` with check name
- FIX ALL: `askyesno` with full list of checks to modify
- UNDO: `askyesno` with complete fix history
- No system changes happen without explicit user confirmation

## Trusted Computing Base

```
Python 3.8+ runtime (trusted)
├── winreg (stdlib — Microsoft)
├── ctypes (stdlib — Python)
├── subprocess (stdlib — Python)
│   └── powershell.exe (OS — signed by Microsoft)
└── threading (stdlib — Python)
```

Only standard-library Python modules and OS-signed binaries are invoked.
No third-party packages, no unsigned code execution.

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Malicious registry modification | All writes enable security features only; no disable/delete operations |
| PowerShell injection | Commands are hardcoded strings with no user input interpolation |
| Race condition on registry | Serial execution within a single thread |
| Undo data loss | Backup happens before every write; multiple writes to same key only store original value once |
| User without admin rights | Clearly blocked at fix time with error guidance |

## Responsible Disclosure

If you discover a security vulnerability in this tool, please open a GitHub
Issue rather than a public discussion. Do not run this tool on a system
without understanding what changes it will make — always review the
confirmation dialog before proceeding.

## Running Safely

```batch
:: Recommended workflow
1. python main.py
2. Click RUN DEEP SCAN (read-only — safe)
3. Review results
4. Select individual checks to fix
5. Read the confirmation dialog carefully
6. Click Yes to apply fixes
7. Use UNDO if anything goes wrong
```
