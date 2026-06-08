# Technology Stack — CISO Advanced Security Auditor

## Runtime

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | **Python 3.8+** | Pre-installed on Windows 10/11; zero deployment cost |
| GUI | **Tkinter / ttk** | Ships with every Python install; sufficient for list+detail layout |
| Threading | **threading** (stdlib) | Tkinter is single-threaded; background threads prevent UI freeze |

## Windows API Surface (stdlib only — no pip packages)

| Module | Used For |
|--------|----------|
| `winreg` | Read/write Windows Registry (95% of checks + all registry fixes) |
| `ctypes.windll.shell32` | Admin privilege check (`IsUserAnAdmin`) |
| `subprocess` | PowerShell invocation (`powershell -NoProfile -Command ...`) |
| `os` | File paths, environment variables, LNK scanning |
| `json` | JSON report export + internal data serialization |
| `csv` | CSV report export |
| `datetime` | Report timestamps |

## No External Dependencies

Every required module is part of the Python Standard Library. This is a
deliberate design constraint:

```
pip freeze  # returns nothing — zero dependencies
```

This ensures:
- Works on any Windows machine with Python 3.8+
- No corporate proxy / firewall blocks for pip
- No version conflicts with other tools
- Can be distributed as a single folder — no setup.py required

## PowerShell Usage

PowerShell is invoked for checks that cannot be done via the Registry alone:

| Check Type | PS Commands Used |
|------------|------------------|
| TPM / BitLocker | `Get-Tpm`, `Get-BitLockerVolume` |
| Firewall | `Get-NetFirewallProfile` |
| AppLocker | `Get-AppLockerPolicy` |
| Defender | `Get-MpComputerStatus`, `Set-MpPreference` |
| Services | `Get-CimInstance Win32_Service` |
| Auditpol | `auditpol /get /subcategory:...` |
| DISM | `dism /online /get-feature` |
| Scheduled Tasks | `Get-ScheduledTask` |
| DNS | `Get-DnsClientServerAddress` |

All PS commands are invoked with `-NoProfile` to skip user profile loading
and `CreationFlags.CREATE_NO_WINDOW` to suppress console flashes.

## Build & Deployment

| Aspect | Approach |
|--------|----------|
| Distribution | Git repo clone + `python main.py` |
| No build step | Pure .py files — no compilation |
| No packaging | No PyInstaller / Nuitka needed (optional for distribution) |
| Version control | Git + GitHub |

## Future Tech Considerations

| Feature | Likely Approach |
|---------|----------------|
| PDF export | `reportlab` (only external dep) or HTML→PDF via Edge WebView2 |
| CI/CD | GitHub Actions — lint + test on push |
| PyInstaller bundle | Single .exe for non-technical users |
| Plug-in system | `importlib` + `.py` files in `plugins/` directory |
| Command-line mode | `argparse` + `--scan`, `--export` flags |
