# Security & Safety — CISO Security Auditor

## The Short Version

This tool changes system settings to make your machine more secure. Every change is reversible. We back up everything before touching it. You can undo anything.

## What the Tool Does

- **Reads** registry keys and runs PowerShell commands to check your security
- **Writes** registry keys to enable security features (UAC, LSA, SMB signing, etc.)
- **Runs PowerShell** to configure Windows features (DISM, Defender, auditpol)
- **Creates** a System Restore Point before fixing anything
- **Backs up** every registry value before changing it

## What the Tool Doesn't Do

- Does NOT delete files or directories
- Does NOT install drivers or kernel modules
- Does NOT modify boot configuration
- Does NOT disable security features (only enables them)
- Does NOT collect or send your data anywhere
- Does NOT need internet access (fully offline)
- Does NOT touch your personal files

## How We Keep You Safe

### 1. Admin Check
- Every fix checks if you're running as admin
- If not admin: fix is blocked with a clear message
- Scanning works without admin (read-only)

### 2. System Restore Point
- Creates a restore point before every fix
- Non-fatal if the restore service is disabled — backup still works

### 3. Registry Backup
- Before writing any registry value, we save the current value
- If something goes wrong, we can restore the original

### 4. UNDO
- Restores every backed-up registry key to its original value
- If there was no previous value, we delete what we added
- All checks reset to PENDING after undo

### 5. Confirmation Dialogs
- Single fix: "Fix this?" with the check name
- Fix all: "Fix all?" with the full list
- Undo: "Undo everything?" with the full history
- Nothing happens without you clicking "Yes"

## What We Use

Only standard Python libraries and Windows system tools:
- `winreg` (Windows registry)
- `ctypes` (admin check)
- `subprocess` (PowerShell commands)
- `threading` (keep UI responsive)
- `powershell.exe` (Windows built-in)

No third-party packages. No unsigned code. No surprises.

## What Could Go Wrong

| Risk | What we do |
|------|-----------|
| Registry write fails | Try/except — tool keeps working |
| PowerShell command fails | We catch it, mark check as WARNING |
| System Restore disabled | Non-fatal — registry backup still works |
| You run without admin | Blocked at fix time with clear message |
| You click the wrong thing | Confirmation dialog before every change |

## How to Use It Safely

1. Run `python main.py`
2. Click **RUN SCAN** (read-only — safe)
3. Look at the results
4. Pick a few things to fix
5. Read the confirmation dialog carefully
6. Click **Yes** to apply fixes
7. Click **UNDO** if anything goes wrong
8. Run the scan again to see your new score
